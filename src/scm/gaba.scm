;; gaba.scm
;;
;; Run with
;;   $ scsh -e main -l scsh-compat.scm -l compiler.scm -s gaba.scm
;;   $ guile -e main -l guile-compat.scm -l compiler.scm -s gaba.scm

;; Reads a C source file on stdin. Comments of the form
;;
;; /*
;; GABA:
;;    expression
;; */
;;
;; are treated specially, and C code for the class is written to
;; stdout. Typically, the code is saved to a file and included by the
;; C source file in question.

;; FIXME: Perhaps the files should somehow be fed through the
;; preprocessor first?

(define (werror f . args)
  (display (apply format #f f args) (current-error-port)))

(define (string-prefix? prefix s)
  (let ((l (string-length prefix)))
    (and (<= l (string-length s))
	 (string=? prefix (substring s 0 l)))))

(define (string-upcase s)
  (list->string (map char-upcase (string->list s))))

(define (read-expression p)
  (let ((line (read-line)))
    ; (werror "read line: '~s'\n" (if (eof-object? line) "<EOF>" line))
    (cond ((eof-object? line) line)
	  ((p line) (read))
	  (else (read-expression p)))))

(define (get key alist select)
  (cond ((assq key alist) => select)
	(else #f)))

(define (append-deep o)
  ; (werror "append-deep: ~S\n" o)
  (cond ((string? o) o)
	((symbol? o) (symbol->string o))
	((number? o) (number->string o))
	(else
	 (apply string-append (map append-deep o)))))

(define (identity x) x)

(define (filter p list)
  (cond ((null? list) list)
	((p (car list)) (cons (car list)
			      (filter p (cdr list))))
	(else (filter p (cdr list)))))

(define (implode list separator)
  (cond ((null? list) '())
	((null? (cdr list)) list)
	(else `(,(car list) ,separator ,@(implode (cdr list) separator)))))

(define (list-prefix l n)
  (if (zero? n) '()
      (cons (car l) (list-prefix (cdr l) (- n 1)))))

(define (atom? o) (not (list? o)))
;; (define (atom? x) (or (symbol? x) (string? x)))

;; Variables are describes as lists (name . type)
;; Known types (and corresponding C declarations) are
;;
;; (string)                     struct lsh_string *name
;; (object class)               struct class *name
;; (bignum)                     mpz_t name
;; (simple c-type)              c-type
;; (special c-type mark-fn free-fn)
;; (indirect-special c-type mark-fn free-fn)
;;
;; (struct tag)
;;
;; (array type size)            type name[size]
;;
;; size-field, when present, is the name of a field that holds
;; the current size of variable size objects.
;;
;; Variable size array (must be last) */
;; (var-array type size-field)  type name[1]
;;
;; FIXME: Split into var-pointer and var-space?
;; (pointer type [size-field])  type *name
;; (space type [size-field])    Like pointer, but should be freed
;;
;; (function type . arg-types) type name(arg-types)
;;
;; NOTE: For function types, the arguments are represented simply as
;; strings or lists containing C declarations; they do not use the
;; type syntax.
;;
;; (method type args)
;; is transformed into (pointer (function type self-arg args)) before
;; processing,

(define (type->category type)
  (if (atom? type)
      (type->category `(simple ,type))
      (let ((tag (car type)))
	(case tag
	  ((string object simple special indirect-special
	    bignum struct) tag)
	  ((array var-array pointer space) (type->category (cadr type)))
	  
	  (else (error "make_class: type->category: Invalid type" type))))))

(define (type->declaration type expr)
  (if (atom? type)
      (type->declaration `(simple ,type) expr)
      (case (car type)
	((string) (list "struct lsh_string *" expr))
	((object) (list "struct " (cadr type) " *" expr))
	((struct) (list "struct " (cadr type) " " expr)) 
	((bignum) (list "mpz_t " expr))
	((simple special indirect-special) (list (cadr type) " " expr))
	((pointer space) (type->declaration (cadr type)
					    (list "(*(" expr "))")))
	((array)  (type->declaration (cadr type)
				     (list "((" expr ")[" (caddr type) "])")))
	((var-array)  (type->declaration (cadr type)
				     (list "((" expr ")[1])")))
	((function) (type->declaration (cadr type)
				       (list expr
					     "(" (implode (cddr type) ", ")
					     ")")))
	(else (error "make_class: type->declaration: Invalid type" type)))))

(define (type->mark type expr)
  (if (atom? type)
      (type->mark `(simple ,type) expr)
      (case (car type)
	((string simple function bignum) #f)
	((object) (list "mark((struct lsh_object *) " expr ");\n"))
	((struct) (list (cadr type) "_mark(&" expr ", mark);\n"))
	((pointer space)
	 (if (null? (cddr type))
	     (type->mark (cadr type) (list "*(" expr ")"))
	     
	     ;; The optional argument should be the name of
	     ;; an instance variable holding the length of
	     ;; the area pointed to
	     (let ((mark-k (type->mark (cadr type)
				       (list "(" expr ")[k]"))))
	       (and mark-k
		    (list "{\n  unsigned k;\n"
			  "  for (k=0; k<i->" (caddr type)
			  "; k++)\n"
			  "    " mark-k
			  "  }\n")))))
	
	((special) (let ((mark-fn (caddr type)))
		     (and mark-fn (list mark-fn "(" expr ", mark);\n"))))
	((indirect-special) (let ((mark-fn (caddr type)))
			      (and mark-fn (list mark-fn "(&(" expr
						 "), mark);\n"))))
	
	;; FIXME: Doesn't handle nested arrays
	((array)
	 (let ((mark-k (type->mark (cadr type) (list "(" expr ")[k]"))))
	   (and mark-k
		(list "{\n  unsigned k;\n"
		      "  for (k=0; k<" (caddr type) "; k++)\n"
		      "    " mark-k
		      "}\n"))))
	((var-array)
	 (let ((mark-k (type->mark (cadr type) (list "(" expr ")[k]"))))
	   (and mark-k
		(list "{\n  unsigned k;\n"
		      "  for (k=0; k<i->" (caddr type) "; k++)\n"
		      "    " mark-k
		      "}\n"))))
	 
	(else (error "make_class: type->mark: Invalid type" type)))))

(define (type->free type expr)
  (define (free/f f)
    (and f (list f "(" expr ");\n")))

  (if (atom? type)
      (type->free `(simple ,type) expr)
      (case (car type)
	;; FIXME: Doesn't free array elements for variables of type space.
	((object simple function pointer) #f)
	((struct) (list (cadr type) "_free(&" expr ");\n"))
	((string) (free/f "lsh_string_free"))
	((bignum) (free/f "mpz_clear"))
	((space) (free/f "lsh_space_free"))
	((special) (free/f (cadddr type)))
	((indirect-special) (let ((free-fn (cadddr type)))
			      (and free-fn
				   (list free-fn "(&(" expr "));\n")))) 
	
	((array)
	 (let ((free-k (type->free (cadr type) (list "(" expr ")[k]"))))
	   (and free-k
		(list "{\n  unsigned k;\n"
		      "  for (k=0; k<" (caddr type) "; k++)\n"
		      "    " free-k
		      "}\n"))))
	((var-array)
	 (let ((free-k (type->free (cadr type) (list "(" expr ")[k]"))))
	   (and free-k
		(list "{\n  unsigned k;\n"
		      "  for (k=0; k<i->" (caddr type) "; k++)\n"
		      "    " free-k
		      "}\n"))))
#!
	((dyn-array)
	 (let ((free-k (type->free (cadr type) (list "(" expr ")[k]"))))
	   (append (if (null? free-k)
		       '("{\n  unsigned k;\n"
			     "  for (k=0; k<i->" (caddr type) "; k++)\n"
			     "    " free-k
			     "}\n")
		       '())
		   (list "lsh_space_free(" expr ");\n")) ))
!#
    
	(else (error "make_class: type->free: Invalid type" type)))))

#!
(define (type->init type expr)
  (if (atom? type)
      (type->init `(simple ,type) expr)
      (case (car type)
	((object string space pointer) (list expr "= NULL;\n"))
	((bignum) (list "mpz_init(" expr ");\n"))
	((array)
	 (let ((init-k (type->init (cadr type) (list "(" expr ")[k]"))))
	   (and init-k
		(list "{\n  unsigned k;\n"
		      "  for (k=0; k<" (caddr type) "; k++)\n"
		      "    " init-k
		      "}\n"))))

	(else (error "make_class: type->init: Invalid type" type)))))
!#

(define var-name car)
(define var-type cdr)

(define (fix-method name var)
  (let ((type (var-type var))
	(variable (var-name var)))
    (if (atom? type)
	var
	(case (car type)
	  ((method)
	   `(,variable pointer (function ,(cadr type)
					 ("struct " ,name " *self")
					 ,@(cddr type))))
	  ((indirect-method)
	   `(,variable pointer (function ,(cadr type)
					 ("struct " ,name " **self")
					 ,@(cddr type))))
	  (else var)))))

(define (do-instance-struct name super vars)
  ; (werror "do-instance-struct\n")
  (list "struct " name 
	"\n{\n"
	"  struct " (or super "lsh_object") " super;\n"
	(map (lambda (var)
	       (list "  " (type->declaration (var-type var)
					     (var-name var)) ";\n"))
	     vars)
	"};\n"))

(define (do-struct name super vars)
  ; (werror "do-struct\n")
  (list "struct " name 
	"\n{\n"
	(map (lambda (var)
	       (list "  " (type->declaration (var-type var)
					     (var-name var)) ";\n"))
	     vars)
	"};\n"))

(define (do-mark-function name vars)
  ; (werror "do-mark-function\n")
  (let ((markers (filter identity
			 (map (lambda (var)
				(type->mark (var-type var)
					    (list "i->" (var-name var))))
			      vars))))
    ; (werror "gazonk\n")
    (and (not (null? markers))
	 (list "static void do_"
	       name "_mark(struct lsh_object *o, \n"
	       "void (*mark)(struct lsh_object *o))\n"
	       "{\n"
	       "  struct " name " *i = (struct " name " *) o;\n"
	       (map (lambda (x) (list "  " x))
		    markers)
	       "}\n\n"))))

(define (do-free-function name vars)
  ; (werror "do-free-function\n")
  (let ((freers (filter identity
			(map (lambda (var)
			       (type->free (var-type var) 
					   (list "i->" (var-name var))))
			     
			     vars))))
    ; (werror "gazonk\n")

    (and (not (null? freers))
	 (list "static void do_"
	       name "_free(struct lsh_object *o)\n"
	       "{\n"
	       "  struct " name " *i = (struct " name " *) o;\n"
	       (map (lambda (x) (list "  " x))
		    freers)
	       "}\n\n"))))

(define (declare-struct-mark-function name)
  (list "void "	name "_mark(struct " name " *i, \n"
	"    void (*mark)(struct lsh_object *o))"))

(define (do-struct-mark-function name vars)
  ; (werror "do-struct-mark-function\n")
  (let ((markers (filter identity
			 (map (lambda (var)
				(type->mark (var-type var)
					    (list "i->" (var-name var))))
			      vars))))
    ; (werror "gazonk\n")
    (list (declare-struct-mark-function name)
	  "\n{\n"
	  ; To avoid warnings for unused parameters
	  "  (void) mark; (void) i;\n"
	  (map (lambda (x) (list "  " x))
	       markers)
	  "}\n\n")))

(define (declare-struct-free-function name)
  (list "void " name "_free(struct " name " *i)"))

(define (do-struct-free-function name vars)
  ; (werror "do-struct-free-function\n")
  (let ((freers (filter identity
			(map (lambda (var)
			       (type->free (var-type var) 
					   (list "i->" (var-name var))))
			     
			     vars))))
    ; (werror "gazonk\n")

    (list (declare-struct-free-function name)
	  "\n{\n"
	  ; To avoid warnings for unused parameters
	  "  (void) i;\n"
	  (map (lambda (x) (list "  " x))
	       freers)
	  "}\n\n")))

(define (do-class name super mark-function free-function meta methods)
  (define initializer
    (list "{ STATIC_HEADER,\n  "
	  (if super
	      ; FIXME: A cast (struct lsh_class *) or something
	      ; equivalent is needed if the super class is not a
	      ; struct lsh_class *. For now, fixed with macros
	      ; expanding to the right component of extended class
	      ; structures.
	      (list "&" super "_class")
	      "0")
	  ", \"" name "\", sizeof(struct " name "),\n  "
	  (if mark-function (list "do_" name "_mark") "NULL") ",\n  "
	  (if free-function (list "do_" name "_free") "NULL") "\n"
	  "}"))
  ; (werror "do-class\n")
  (if meta
      (list "struct " meta "_meta " name "_class_extended =\n"
	    "{ " initializer 
	    (if methods
		(map (lambda (m) (list ",\n  " m)) methods)
		"")
	    "};\n")
      (list "struct lsh_class " name "_class =\n"
	    initializer ";\n")))

(define (process-class attributes)
  (let ((name (get 'name attributes cadr))
	(super (get 'super attributes cadr))
	(raw-vars (get 'vars attributes cdr))
	(meta (get 'meta attributes cadr))
	(methods (get 'methods attributes cdr)))
    (werror "Processing class ~S\n" name)
    ; (werror "foo\n")
    (let ((vars (map (lambda (var) (fix-method name var))
		     raw-vars)))
      (let ((mark-function (do-mark-function name vars))
	    (free-function (do-free-function name vars)))
	; (werror "baar\n")
	(list "#ifndef GABA_DEFINE\n"	
	      (do-instance-struct name super vars)
	      (if meta
		  (list "extern struct " meta "_meta "
			name "_class_extended;\n"
			"#define " name "_class (" name "_class_extended.super)\n")
		  (list "extern struct lsh_class " name "_class;\n"))
	      "#endif /* !GABA_DEFINE */\n\n"
	      "#ifndef GABA_DECLARE\n"
	      (or mark-function "")
	      (or free-function "")
	      (do-class name super mark-function free-function
			meta methods)
	      "#endif /* !GABA_DECLARE */\n\n")))))

(define (process-meta attributes)
  (let ((name (get 'name attributes cadr))
	(methods (get 'methods attributes cdr)))
    (werror "Processing meta ~S\n" name)
    (list "#ifndef GABA_DEFINE\n"
	  "struct " name "_meta\n"
	  "{\n"
	  "  struct lsh_class super;\n"
	  (map (lambda (m) (list "  " m ";\n"))
	       methods)
	  "};\n"
	  "#endif /* !GABA_DEFINE */\n\n")))

(define (process-struct attributes)
  (let ((name (get 'name attributes cadr))
	;; FIXME: Do we really handle super?
	(super (get 'super attributes cadr))
	(raw-vars (get 'vars attributes cdr))
	(meta (get 'meta attributes cadr))
	(methods (get 'methods attributes cdr)))
    (werror "Processing struct ~S\n" name)
    ; (werror "foo\n")
    ;; FIXME: Is this really needed?
    (let ((vars (map (lambda (var) (fix-method name var))
		     raw-vars)))
      ; (werror "baar\n")
      (list "#ifndef GABA_DEFINE\n"	
	    (do-struct name super vars)
	    "extern " (declare-struct-mark-function name) ";\n"
	    "extern " (declare-struct-free-function name) ";\n"
	    "#endif /* !GABA_DEFINE */\n\n"
	    "#ifndef GABA_DECLARE\n"
	    (do-struct-mark-function name vars)
	    (do-struct-free-function name vars)
	    "#endif /* !GABA_DECLARE */\n\n"))))

;;;; Expression compiler

;; Can't use load; it writes messages to stdout.
;;(load 'compiler)


;; Constants is an alist of (name value call_1 call_2 ... call_n)
;; where value is a C expression representing the value. call_i is
;; present, it is a function that can be called to apply the value to
;; i arguments directly.
(define (make-output constants)
  ;; OP and ARGS are C expressons
  (define (apply-generic op args)
    ;; (werror "(apply-generic ~S)\n" (cons op args))
    (if (null? args) op
	(apply-generic (list "A(" op ", " (car args) ")")
		       (cdr args))))
  ;; INFO is the (value [n]) associated with a constant,
  ;; and ARGS is a list of C expressions
  (define (apply-constant info args)
    ;; (werror "apply-constant : ~S\n" info)
    ;; (werror "          args : ~S\n" args)
    (let ((calls (cdr info)))
      (if (null? calls)
	(apply-generic (car info) args)
	(let ((n (min (length calls) (length args))))
	  ;; (werror "n: ~S\n" n)
	  (apply-generic (list (nth info n)
			       "(" (implode (list-prefix args n) ", ") ")")
			 (list-tail args n))))))
  (define (lookup-global v)
    (cond ((assq v constants) => cdr)
	  (else (list (string-upcase (symbol->string v))))))
  
  (define (output-expression expr)
    ;; (werror "output-expression ~S\n" expr)
    (if (atom? expr)
	(car (lookup-global expr))
	(let ((op (application-op expr))
	      (args (map output-expression (application-args expr))))
	  (if (atom? op)
	      (apply-constant (lookup-global op) args)
	      (apply-generic op args)))))
  output-expression)

(define (process-expr attributes)
  (define (declare-params params)
    (implode (map (lambda (var)
		    (type->declaration (var-type var)
				       (var-name var)))
		  params)
	     ", "))
  (define (params->alist params)
    (map (lambda (var)
	   (let ((name (var-name var)))
	     (list name (list "((struct lsh_object *) " name ")" ))))
	 params))
  
  ;; (werror "foo\n")
  (let ((name (get 'name attributes cadr))
	(globals (or (get 'globals attributes cdr) '()))
	(params (get 'params attributes cdr))
	(expr (get 'expr attributes cadr)))
    (werror "Processing expression ~S\n" name)
    (let ((translated (translate expr)))
      (werror "Compiled to ~S\n" translated)
      (list "static struct lsh_object *\n" name "("
	    (if params (declare-params params) "void")
	    ")\n{\n"
	    (format #f "  /* ~S */\n" translated)
	    "#define A GABA_APPLY\n"
	    "#define I GABA_VALUE_I\n"
	    "#define K GABA_VALUE_K\n"
	    "#define K1 GABA_APPLY_K_1\n"
	    "#define S GABA_VALUE_S\n"
	    "#define S1 GABA_APPLY_S_1\n"
	    "#define S2 GABA_APPLY_S_2\n"
	    "#define B GABA_VALUE_B\n"
	    "#define B1 GABA_APPLY_B_1\n"
	    "#define B2 GABA_APPLY_B_2\n"
	    "#define C GABA_VALUE_C\n"
	    "#define C1 GABA_APPLY_C_1\n"
	    "#define C2 GABA_APPLY_C_2\n"
	    "#define Sp GABA_VALUE_Sp\n"
	    "#define Sp1 GABA_APPLY_Sp_1\n"
	    "#define Sp2 GABA_APPLY_Sp_2\n"
	    "#define Sp3 GABA_APPLY_Sp_3\n"
	    "#define Bp GABA_VALUE_Bp\n"
	    "#define Bp1 GABA_APPLY_Bp_1\n"
	    "#define Bp2 GABA_APPLY_Bp_2\n"
	    "#define Bp3 GABA_APPLY_Bp_3\n"
	    "#define Cp GABA_VALUE_Cp\n"
	    "#define Cp1 GABA_APPLY_Cp_1\n"
	    "#define Cp2 GABA_APPLY_Cp_2\n"
	    "#define Cp3 GABA_APPLY_Cp_3\n"
	    ;; "  trace(\"Entering " name "\\n\");\n"
	    "  return MAKE_TRACE(\"" name "\", \n    "
	    ((make-output (append '( (I I)
				     (K K K1)
				     (S S S1 S2)
				     (B B B1 B2)
				     (C C C1 C2)
				     (S* Sp Sp1 Sp2 Sp3)
				     (B* Bp Bp1 Bp2 Bp3)
				     (C* Cp Cp1 Cp2 Cp3))
				  globals
				  (if params
				      (params->alist params)
				      '())))
	     translated)
	    "\n  );\n"
	    "#undef A\n"
	    "#undef I\n" 
	    "#undef K\n"
	    "#undef K1\n"
	    "#undef S\n"
	    "#undef S1\n"
	    "#undef S2\n"
	    "#undef B\n"
	    "#undef B1\n"
	    "#undef B2\n"
	    "#undef C\n"
	    "#undef C1\n"
	    "#undef C2\n"
	    "#undef Sp\n"
	    "#undef Sp1\n"
	    "#undef Sp2\n"
	    "#undef Sp3\n"
	    "#undef Bp\n"
	    "#undef Bp1\n"
	    "#undef Bp2\n"
	    "#undef Bp3\n"
	    "#undef Cp\n"
	    "#undef Cp1\n"
	    "#undef Cp2\n"
	    "#undef Cp3\n"
	    "}\n"))))

(define (process-input exp)
  (let ((type (car exp))
	(body (cdr exp)))
    ;; (werror "process-class: type = ~S\n" type)
    (case type
      ((class) (process-class body))
      ((meta) (process-meta body))
      ((struct) (process-struct body))
      ((expr) (process-expr body))
      (else (list "#error Unknown expression type " type "\n")))))

(define main
  (let ((test (lambda (s) (string-prefix? "/* GABA:" s))))
    (lambda args
      (let ((exp (read-expression test)))
	(if (not (eof-object? exp))
	    (begin
	      (display (append-deep (process-input exp)))
	      (main)))))))

; (main)
