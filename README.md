# cl-openbsd-security
Common lisp bindings for OpenBSD [pledge(2)](https://man.openbsd.org/pledge.2) and [unveil(2)](https://man.openbsd.org/unveil.2)

Makes it easier to call pledge and unveil in a lispier way:

```
(obsd:pledge stdio prot-exec rpath) ;;for promisses only, no execpromisses

(obsd:pledge (stdio exec prot-exec xpath) (stdio wpath)) ;; for promisses and execpromisses

(obsd:unveil #p"/tmp" 'rwc)
```

Signals compile time errors when you make a typo
```
(obsd:pledge executive nonsense) ;; does not compile

(obsd:unveil #p"/home/me" 'read) ;; does not run
```

## Install

Install with asdf: clone to `~/common-lisp` or elswhere where your asdf looks, then `(asdf:make :cl-openbsd-security)`.
Not on quicklisp (yet?).

## Limitations

* Obviously only usable on OpenBSD. Will fail on any other OS. If you want to use this opportunistically, detect OS before use.
* Works with all common lisp implementations available in OpenBSD ports for
  amd64:
  - SBCL
  - ECL
  - CLISP
  - ABCL (`pkg-add -i jna` before use or otherwise get jna on classpath)
  
  _of course the minimal set of pledges differs on different implementations_
