;; FIXME: Turn this into a scheme48 module

(define (atom? o) (not (list? o)))
(define (lambda? o) (and (pair? o) (eq? 'lambda (car o))))

(define (make-lambda formal body) `(lambda ,formal ,body))
(define lambda-formal cadr)
(define lambda-body caddr)

(define make-appliction list)
(define application-op car)
(define application-arg cadr)
(define application-args cdr)

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

(define (translate-lambda v expr)
  (if (not (free-variable? v expr))
      (make-combine 'K (translate-expression expr))
      (cond ((atom? expr)
	     (if (eq? v expr) 'I
		 (error "translate normal: unexpected bound variable")))
	    ((lambda? expr)
	     ;; Depth first
	     (translate-lambda v
			       (translate-lambda (lambda-formal expr)
						 (lambda-body expr))))
	    ;; Must be an application
	    (else
	     (let ((op (application-op expr))
		   (arg (application-arg expr)))
	       (if (and (eq? v arg)
			(not (free-variable? v op)))
		   (translate-expression op)
		   (make-combine 'S
				 (translate-lambda v op)
				 (translate-lambda v arg))))))))

(define (translate-expression expr)
  (cond ((atom? expr) expr)
	((lambda? expr)
	 (translate-lambda (lambda-formal expr)
			   (lambda-body expr)))
	(else
	 (make-appliction (translate-expression (application-op expr))
			  (translate-expression (application-arg expr))))))

(define (make-flat-application op arg)
  (if (atom? op) `(,op ,arg)
      `(,@op ,arg)))
      
(define (flatten-application expr)
  (if (or (atom? expr) (lambda? expr)) expr
      (make-flat-application (flatten-application (application-op expr))
			     (flatten-application (application-arg expr)))))

;; Could do some rewriting
(define (optimize expr) expr)

(define (translate expr)
  (optimize (flatten-application (translate-expression (preprocess expr)))))

		   
	
