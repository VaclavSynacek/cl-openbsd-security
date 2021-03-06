(in-package :cl-user)

(defpackage :cl-openbsd-security-free-test
  (:use :cl :uiop))

(in-package :cl-openbsd-security-free-test)


(defun test-program-with-pledge (cl-string program-string promises exec-promises)
  (let*
    ((promises-string (format nil "(~{~a~^ ~})" promises))
     (exec-promises-string (format nil "(~{~a~^ ~})" exec-promises))
     (full-program-string (format nil
                                  "
(unless (asdf:make :cl-openbsd-security)
  (quit))
(obsd:pledge ~a ~a)
(progn
  ~a
  (princ \"we got past pledge\")
  (quit))
                                  "
                                  promises-string
                                  exec-promises-string
                                  program-string))
     (output (uiop:run-program cl-string
                              :ignore-error-status t
                              :output :string
                              :force-shell nil
                              :input
                              (make-string-input-stream full-program-string))))
  ; (format t "INPUT: ~a ~%~%**************************~%~%" full-program-string)
  ; (format t "OUTPUT: ~a ~%~%*************************~%~%" output)
    (when (search "we got past pledge" output)
       t)))


(test-program-with-pledge
  "clisp"
  "(format t \"Hooray~%\")"
  cl-openbsd-security::pledges
  cl-openbsd-security::pledges)

(test-program-with-pledge
  "sbcl"
  "(format t \"Hooray~%\")"
  cl-openbsd-security::pledges
  cl-openbsd-security::pledges)

(test-program-with-pledge
  "sbcl"
  "(format t \"Hooray~%\")"
  '(rpath)
  '())


(defun get-minimal-pledge (cl-string program-string)
  (let
    ((to-test cl-openbsd-security::pledges)
     (required (list)))
    (dolist (p to-test)
      (unless (test-program-with-pledge
                cl-string
                program-string
                (remove p to-test)
                '())
        (push p required)))
    required))


(get-minimal-pledge
  "sbcl"
  "(with-open-file (f \"/tmp/file.f\"
                       :direction :output
                       :if-exists :supersede
                       :if-does-not-exist :create)
     (format f \"write anything ~a ~%\" (random 100)))
   (delete-file \"/tmp/file.f\")")  
