;; FIXME: Turn this into a scheme48 module

(define-syntax let-and
  (syntax-rules '()
		((let-and (expr) clause clauses ...)
		 (if expr (let-and clause clauses ...)
		     #f))
		((let-and (name expr) clause clauses ...)
		 (let ((name expr))
		   (if name (let-and clause clauses ...) #f)))
		((let-and expr) expr)))

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
	 (do-lambda (reverse (lambda-formal expr))
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

#!
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

!#

(define (match pattern expr)
  (if (atom? pattern)
      (if (eq? '* pattern) (list expr)
	  (and (eq? pattern expr) '()))
      (let-and ((pair? expr))
	       (op-matches (match (application-op pattern)
				  (application-op expr)))
	       (arg-matches (match (application-arg pattern)
				   (application-arg expr)))
	       (append op-matches arg-matches))))

(define (rule pattern f)
  (cons (preprocess pattern) f))

(define (make-K e) (make-combine 'K e))
(define (make-S p q) (make-combine 'S p q))
(define (make-B p q) (make-combine 'B p q))
(define (make-C p q) (make-combine 'C p q))
(define (make-S* p q r) (make-combine 'S* p q r))
(define (make-B* p q r) (make-combine 'B* p q r))
(define (make-C* p q r) (make-combine 'C* p q r))

(define optimizations
  (list (rule '(S (K *) (K *)) (lambda (p q) (make-K (make-appliction p q))))
	(rule '(S (K *) I) (lambda (p) p))
	(rule '(S (K *) (B * *)) make-B*)
	(rule '(S (K *) *) make-B)
	;; (rule '(S (B * *) (K *)) make-C*)
	(rule '(C (B * *) *) make-C*)
	(rule '(S * (K *)) make-C)
	(rule '(S (B * * ) *) make-S*)))

(define (optimize expr)
  (werror "optimize ~S\n" expr)
  (let loop ((rules optimizations))
    (if (not (null? rules)) (werror "trying pattern ~S\n" (caar rules)) )
    (cond ((null? rules) expr)
	  ((match (caar rules) expr)
	   => (lambda (parts) (apply (cdar rules) parts)))
	  (else (loop (cdr rules))))))

(define (make-combine op . args)
  (optimize (normalize-application op args)))

(define (translate-expression expr)
  (cond ((atom? expr) expr)
	((lambda? expr)
	 (translate-lambda (lambda-formal expr)
			   (translate-expression (lambda-body expr))))
	(else
	 (make-appliction (translate-expression (application-op expr))
			  (translate-expression (application-arg expr))))))

(define (translate-lambda v expr)
  (cond ((atom? expr)
	 (if (eq? v expr) 'I (make-K expr)))
	((lambda? expr)
	 (error "translate-lambda: Unexpected lambda" expr))
	(else
	 (make-S (translate-lambda v (application-op expr))
		       (translate-lambda v (application-arg expr))))))
  
(define (make-flat-application op arg)
  (if (atom? op) `(,op ,arg)
      `(,@op ,arg)))
      
(define (flatten-application expr)
  (if (or (atom? expr) (lambda? expr)) expr
      (make-flat-application (flatten-application (application-op expr))
			     (flatten-application (application-arg expr)))))

(define (translate expr)
  (flatten-application (translate-expression (preprocess expr))))

;;; Test cases
