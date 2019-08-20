(asdf:defsystem #:cl-openbsd-security
  :description "Bindings for OpenBSD's pledge(2) and unveil(2)"
  :author "Vaclav Synacek"
  :license  "ISC"
  :version "0.0.1"
  :depends-on ( "cffi" "trivial-features" )
  :serial t
  :components ((:file "cl-openbsd-security")))
