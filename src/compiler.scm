;; FIXME: Turn this into a scheme48 module

(define-syntax let-and
  (syntax-rules '()
		((let-and (expr) clause clauses ...)
		 (and expr (let-and clause clauses ...)))
		((let-and (name expr) clause clauses ...)
		 (let ((name expr))
		   (and name (let-and clause clauses ...))))
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
(define (make-preprocess specials)

  (define (preprocess expr)
    (if (atom? expr) expr
	(let ((op (car expr)))
	  (cond ((and (atom? op)
		      (assq op specials))
		 => (lambda (pair) ((cdr pair) (cdr expr) preprocess)))
		(else
		 (normalize-application (preprocess op)
					(map preprocess (cdr expr))))))))
  preprocess)

(define preprocess-applications (make-preprocess '()))

(define (do-lambda args preprocess)
  (let loop ((formals (reverse (car args)))
	     (body (preprocess (cadr args))))
    (if (null? formals) body
	(loop (cdr formals)
	      (make-lambda (car formals) body)))))

(define (do-let* args preprocess)
  (let loop ((definitions (reverse (car args)))
	     (body (preprocess (cadr args))))
    (if (null? definitions) body
	(loop (cdr definitions)
	      (make-appliction
	       (make-lambda (caar definitions)
			    body)
	       (preprocess (cadar definitions)))))))

(define (do-let args preprocess)
  (let ((definitions (car args))
	(body (cadr args)))
    (normalize-application 
     (do-lambda (list (map car definitions) body) preprocess)
     (map cadr definitions))))

(define preprocess (make-preprocess
		    `((lambda . ,do-lambda)
		      (let . ,do-let)
		      (let* . ,do-let*))))
  
(define (free-variable? v expr)
  (cond ((atom? expr) (eq? v expr))
	((lambda? expr)
	 (and (not (eq? v (lambda-formal expr)))
	      (free-variable? v (lambda-body expr))))
	(else
	 (or (free-variable? v (application-op expr))
	     (free-variable? v (application-arg expr))))))

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
  (cons (preprocess-applications pattern) f))

(define (make-K e) (make-combine 'K e))
(define (make-S p q) (make-combine 'S p q))
;; (define (make-B p) (make-combine 'B p))
;; (define (make-C p q) (make-combine 'C p q))
;; (define (make-S* p q) (make-combine 'S* p q))
;; (define (make-B* p q) (make-combine 'B* p q))
;; (define (make-C* p q) (make-combine 'C* p q))

;; Some mor patterns that can ba useful for optimization. From "A
;; combinator-based compiler for a functional language" by Hudak &
;; Kranz.

;; S K => K I
;; S (K I) => I
;; S (K (K x)) => K (K x)
;; S (K x) I => x
;; S (K x) (K y) => K (x y)
;; S f g x = f x (g x)
;; K x y => x
;; I x => x
;; Y (K x) => x

(define optimizations
  (list (rule '(S (K *) (K *)) (lambda (p q) (make-K (make-appliction p q))))
	(rule '(S (K *) I) (lambda (p) p))
	;; (rule '(B K I) (lambda () 'K))
	(rule '(S (K *) (B * *)) (lambda (p q r) (make-combine 'B* p q r)))
	(rule '(S (K *) *) (lambda (p q) (make-combine 'B p q)))
	(rule '(S (B * *) (K *))  (lambda (p q r) (make-combine 'C* p q r)))
	;; (rule '(C (B * *) *) (lambda (p q r) (make-combine 'C* p q r)))
	(rule '(S * (K *)) (lambda (p q) (make-combine 'C p q)))
	(rule '(S (B * * ) r) (lambda (p q r) (make-combine 'S* p q r)))))

(define (optimize expr)
  ;; (werror "optimize ~S\n" expr)
  (let loop ((rules optimizations))
    ;; (if (not (null? rules)) (werror "trying pattern ~S\n" (caar rules)) )
    (cond ((null? rules) expr)
	  ((match (caar rules) expr)
	   => (lambda (parts) (apply (cdar rules) parts)))
	  (else (loop (cdr rules))))))

(define (optimize-application op args)
  (if (null? args) op
      (optimize-application (optimize (make-appliction op (car args)))
			    (cdr args))))

(define (make-combine op . args)
  (optimize-application op args))

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
;; (translate '(lambda (port connection)
;;                 (start-io (listen port connection)
;;                 (open-direct-tcpip connection))))
;;  ===> (C (B* S (B start-io) listen) open-direct-tcpip)
;; 
;; (translate '(lambda (f) ((lambda (x) (f (lambda (z) ((x x) z))))
;; 			    (lambda (x) (f (lambda (z) ((x x) z)))) )))
;; ===> (S (C B (S I I)) (C B (S I I)))
;; 
;; (translate '(lambda (r) (lambda (x) (if (= x 0) 1 (* x (r (- x 1)))))))
;; ===> (B* (S (C* if (C = 0) 1)) (S *) (C B (C - 1)))
