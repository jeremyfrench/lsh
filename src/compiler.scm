(define (atom? o) (not (list? o)))
(define (lambda? o) (and (pair? o) (eq? 'lambda (car o))))

(define (make-lambda formal body) `(lambda ,formal ,body))
(define lambda-formal cadr)
(define lambda-body caddr)

(define make-appliction list)
(define application-op car)
(define application-arg cadr)

(define (normalize-application op args)
  (if (null? args) op
      (normalize-application (make-appliction op (car args)) (cdr args))))

;; Transform (a b c)-> ((a b) c) and
;; (lambda (a b) ...) -> (lambda a (lambda b ...)
(define (preprocess expr)
  (define (do-lambda formals body)
    (if (null? formals) body
	(do-lambda (cdr formals) (make-lambda (car formals) body))))
  (cond ((atom? expr) expr)
	((lambda? expr)
	 (do-lambda (lambda-formal expr)
		    (preprocess (lambda-body expr))))
	(else
	 (normalize-application (preprocess (car expr))
				(map preprocess (cdr expr))))))

(define (free-variable? v expr)
  (cond ((atom? expr) (eq? v expr))
	((lambda? expr)
	 (and (not (eq? v (lambda-formal expr)))
	      (free-variable? v (lambda-body expr))))
	(else
	 (or (free-variable? v (application-op expr))
	     (free-variable? v (application-arg expr))))))

(define (make-combine op . args)
  (normalize-application op args))

(define (translate-normal v expr)
  (if (not (free-variable? v expr))
      (make-combine 'K expr)
      (cond ((atom? expr)
	     (if (eq? v expr) 'I
		 (error "translate normal: unexpected bound variable")))
	    ((lambda? expr)
	     ;; Depth first
	     (translate-normal v
			       (translate-normal (lambda-formal expr)
						 (lambda-body expr))))
	    ;; Must be an application
	    (else
	     (let ((op (application-op expr))
		   (arg (application-arg expr)))
	       (if (and (eq? v arg)
			(not (free-variable? v op)))
		   op
		   (make-combine 'S
				 (translate-normal v op)
				 (translate-normal v arg))))))))

(define (translate expr)
  (let ((input (preprocess expr)))
    (if (lambda? input)
	(translate-normal (lambda-formal input)
			  (lambda-body input))
	(error "translate:Not a lambda expression"))))
