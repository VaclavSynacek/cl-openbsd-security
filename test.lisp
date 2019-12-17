(ql:quickload :prove)


(in-package :cl-user)
(defpackage cl-openbsd-security/test
  (:use :cl
        :prove
        :cl-openbsd-security))
(in-package :cl-openbsd-security/test)


(subtest "should run anywhere"
  (subtest "helper pure functions"
    (is-type
      (obsd::symbols-to-promise-long-string obsd::pledges)
      'string
      "correct promisses are converted to string")
    (is-error
      (obsd::symbols-to-promise-long-string non-sense non-existent bullshit)
      't
      "incorrect promisses signal condition")
    (is-type
      (obsd::permissions-to-valid-string 'rwxc)
      'string
      "correct promisses are converted to string")
    (is-error
      (obsd::permissions-to-valid-string bullshit)
      't
      "incorrect promisses signal condition"))
  (subtest "compilation time tests"
    (ok (macroexpand `(pledge stdio)) "pledge example")
    (ok (macroexpand `(pledge ,obsd::pledges)) "pledge with all possible pledges")
    (ok (macroexpand `(pledge ,obsd::pledges ,obsd::pledges)) "pledge with all possible pledges and execpledges")
    (is-error (macroexpand `(pledge non-sense non-existent bullshit)) t "incorrect promisses signal condition")
    (is-error (macroexpand `(pledge (stdio exec) (stdio non-sense non-existent bullshit))) t "incorrect exec promisses signal condition")
    (is-error (macroexpand `(pledge (stdio exec bulshit) (stdio))) t "incorrect promisses with correct exec-promisses still signal condition")))











