#|
 | Copyright (c) 2019 Vaclav Synacek
 |
 | Permission to use, copy, modify, and distribute this software for any
 | purpose with or without fee is hereby granted, provided that the above
 | copyright notice and this permission notice appear in all copies.
 |
 | THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 | WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 | MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 | ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 | WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 | ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 | OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 |#

(defpackage :cl-openbsd-security
  (:nicknames :openbsd :obsd)
  (:use :common-lisp :cffi)
  (:export
    :pledge
    :pledge-raw
    :unveil
    :unveil-raw))
   
(in-package :cl-openbsd-security)


(defparameter pledges (list 'stdio 'rpath 'wpath 'cpath 'dpath 'tmppath 'inet 'mcast 'fattr 'chown 'flock 'unix 'dns 'getpw 'sendfd 'recvfd 'tape 'tty 'proc 'exec 'prot-exec 'settime 'ps 'vminfo 'id 'pf 'audio 'video 'bpf 'unveil))


(define-condition cl-openbsd-security-condition (warning)
  ((message :initarg :message
    :reader message))
  (:documentation "General condition for the :cl-openbsd-security package"))

(define-condition runtime-security-condition (cl-openbsd-security-condition)
  ((message :initarg :message
    :reader message))
  (:report (lambda (condition stream)
             (format stream "Some OpenBSD security mitigation failed.
  You probably can continue, but some of the security guarantees will not be honored.
  The datail is: ~a~%" (message condition))))
  (:documentation "Runtime condition for the :cl-openbsd-security package. Used
                  when runtime call to pledge(2) or unveil(2) fails."))

(define-condition security-compilation-error (cl-openbsd-security-condition)
  ((message :initarg :message
    :reader message))
  (:report (lambda (condition stream)
             (format stream "Cannot compile cl-openbsd-security macro.
  The datail is: ~a~%" (message condition))))
  (:documentation "Compile-time condition for the :cl-openbsd-security package. Used
                  when  pledge(2) or unveil(2) is poorly defined or has typos."))


(defun interpret-result (c-result-code &optional (call "last security"))
  (if (zerop c-result-code)
    t
    (let*
      ((errno (mem-ref (foreign-funcall "__errno" (:pointer :int)) :int))
       (error-message (foreign-funcall "strerror" :int errno :string))
       (detail-reason (format nil "~a call failed - ~a" call error-message)))
      (cerror
        (format nil "Continue while ignoring that ~a" detail-reason)
        'runtime-security-condition
        :message detail-reason))))
   

(defcfun (pledge-raw "pledge") :int
  "Restrict system operations to promises."
  (promises :string)
  (execpromises :string))

(defun symbol-to-string (symbol)
  (substitute #\_ #\-
    (format nil "~(~A~)"
      (string symbol))))

(defun symbols-to-promise-long-string (list-of-symbols)
  (let
    ((formated-strings
      (mapcar
        #'symbol-to-string
        list-of-symbols)))
    (unless (subsetp
              formated-strings
              (mapcar #'symbol-to-string pledges)
              :test #'equal)
      (cerror "Ignore, compile to invalid string, expect runtime errors later."
              'security-compilation-error
              :message
              (format nil
                      "tryng to pladge invalid promisses: ~{~a~^, ~}"
                      (set-difference formated-strings pledges :test #'equal))))
    (format nil "~{~a~^ ~}" formated-strings)))


(defmacro pledge (&rest all-promisses)
  (if (and
        (every #'symbolp all-promisses)
        (notany #'null all-promisses))
      `(pledge ,all-promisses nil)
      (let
        ((promisses (first all-promisses))
         (exec-promisses (second all-promisses)))
        `(interpret-result
           (pledge-raw
             ,(if promisses
                (symbols-to-promise-long-string promisses)
                '(null-pointer))
             ,(if exec-promisses
                (symbols-to-promise-long-string exec-promisses)
                '(null-pointer)))
           "pledge")))) 


(defcfun (unveil-raw "unveil") :int
  "unveil parts of a restricted filesystem view"
  (path :string)
  (permissions :string))

(defun permissions-to-valid-string (permissions)
  (let
    ((string-permissions (ctypecase permissions
                           (string permissions)
                           (symbol (format nil
                                      "~(~a~)"
                                      (string permissions))))))
    (unless (subsetp
              (coerce string-permissions 'list)
              (list #\r #\w #\x #\c)
              :test #'equal)
     (cerror "Ignore, compile to invalid string, expect runtime errors later."
             'security-compilation-error
             :message
             (format nil
                     "tryng to unveil with invalid rigths ~{~a~^, ~}"
                     (set-difference
                       (coerce string-permissions 'list)
                       (list #\r #\w #\x #\c)
                       :test #'equal))))
    string-permissions))

(defun unveil (path permissions)
  (let
    ((string-path (ctypecase path
                    (string path)
                    (pathname (namestring path))))
     (string-permissions (permissions-to-valid-string permissions)))
    (interpret-result
      (unveil-raw string-path string-permissions)
      "unveil")))

#|

(foreign-symbol-pointer "pledge")

(pledge stdio rpath wpath cpath dpath tmppath inet mcast fattr chown flock unix dns getpw sendfd recvfd tape tty proc exec prot_exec settime ps vminfo id pf audio video bpf unveil)


;; CLISP OK
(pledge stdio rpath wpath cpath dpath tmppath inet mcast flock unix getpw sendfd recvfd tty proc exec prot_exec ps vminfo id unveil)

;; CLISP OK
(pledge stdio inet mcast flock unix getpw sendfd recvfd tty proc exec prot_exec ps vminfo id unveil)


;; CLISP OK
(pledge stdio mcast flock unix getpw sendfd recvfd tty proc exec prot_exec ps vminfo id)


;; CLISP OK
(pledge stdio mcast flock unix getpw tty proc exec prot_exec ps vminfo id)

;; CLISP OK
(pledge stdio mcast flock unix getpw tty proc exec prot_exec)

;; CLISP OK
(pledge stdio mcast flock unix proc tty exec prot_exec)


;; CLISP OK - MINIMAL CLISP PROMISSES
(pledge stdio tty)




(pledge stdio rpath wpath cpath dpath tmppath inet prot_exec)

(pledge blbost)


(macroexpand
  '(pledge (stdio rpath) (stdio wpath)))

(pledge stdio rpath exec exec-prot)

(pledge blbost)

(pledge (stdio rpath exec) (stdio))

(macroexpand '(pledge stdio wpath))

(macroexpand '(pledge (stdio) ()))

(macroexpand '(pledge (stdio) nil))

(pledge (stdio) nil)

(macroexpand '(pledge (stdio wpath exec) (stdio rpath)))

(pledge-raw "stdio stdio" (null-pointer))

(pledge-raw "stdio rpath exec prot_exec" (null-pointer))

(pledge-raw "stdio rpath wpath cpath dpath exec proc sendfd recvfd unix fattr" "unix fattr sendfd recvfd stdio rpath wpath cpath dpath exec proc")

(unveil-raw "/home" "rw")

(unveil #p"/tmp/" 'r)

(uiop:directory-files "./")

(uiop:directory-files "/tmp/")

(uiop:subdirectories "/home")


(type-of (first (uiop:directory-files "/home/jajis/projects")))


|#
