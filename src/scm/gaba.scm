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

(define-syntax when
  (syntax-rules ()
    ((when <cond> . <body>)
     (if <cond> (begin . <body>)))))

(define-syntax unless
  (syntax-rules ()
    ((unless <cond> . <body>)
     (if (not <cond>) (begin . <body>)))))

  
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
;;
;; (const . type)               Like type, but declared const.
;;                              Primarily used for const string.

;;; C code generation

;; A portion of C code is represented as a either
;;
;; an atom (string, symbol or number), or
;;
;; procedure taking a single INDENT argument, sending
;; output to current-output-stream, or
;;
;; a list, whose elements are displayed indented one more level.
;;
;; It would be cleaner to let indent be a dynamically bound variable.

(define (out level . args)
  (for-each (lambda (o)
	      (cond ((procedure? o) (o level))
		    ((list? o) (apply out (+ 1 level) o))
		    (else (display o))))
	    args))

; This isn't very optimal
(define (indent i)
  (display "\n")
  (let loop ((count 0))
    (when (< count i)
	  (display "  ")
	  (loop (+ 1 count)))))
	     
#!
(define-syntax cdef
  (syntax-rules () ((cdef <i> <spec>
			  <body>)
		    (define <spec>
		      (lambda <i> <body>)))))
!#
(define (c-append . args)
  (lambda (i) (apply out i args)))

(define (c-var name) name)

(define (c-string name)
  ;; FIXME: Could do quoting better
  (c-append "\"" name "\""))

(define (c-statement expr)
  (c-append expr ";"))

(define (c-address expr)
  (c-append "&(" expr ")"))

(define (c-nl o)
  (c-append o indent))

(define (c-list separator list)
      (if (null? list) '()
	  (cons (car list)
		(map (lambda (o)
		       (c-append separator o))
		     (cdr list)))))

(define (c-list* separator . list) (c-list separator list))

(define (c-block statements)
  (c-append "{" (map (lambda (s) (c-append indent s ";"))
		     statements)
	    indent "}"))

(define (c-block* . statements) (c-block statements))

(define (c-initializer expressions)
  (c-append "{" (map (lambda (s) (c-append indent s ","))
		     expressions)
	    indent "}"))

(define (c-initializer* . expressions) (c-initializer expressions))

(define (c-prototype return name . args)
  (c-append return indent name
	    "("
	    (if (null? args) "void" (c-list (c-nl ",") args))
	    ")"))

(define (c-for var range body)
  (c-append "for(" var "=0; "
	    var "<" range "; "
	    var "++)"
	    indent (list body)))

(define (c-call f . args)
  (c-append f "(" (c-list (c-append "," indent) args) ")"))

(define (c-declare var)
  (define (c-decl-1 type expr)
    (case (car type)
      ((simple special indirect-special)
       (c-append (cadr type) " " expr))
      ((string)
       (c-append "struct lsh_string *" expr))
      ((object)
       (c-append "struct " (cadr type) " *" expr))
      ((struct)
       (c-append "struct " (cadr type) " " expr))
      ((bignum)
       (c-append "mpz_t " expr))
      ((pointer space)
       (c-decl-1 (cadr type) 
		 (c-append "(*(" expr "))")))
      ((array)
       (c-decl-1 (cadr type)
		 (c-append "((" expr ")[" (caddr type) "])")))
      ((var-array)
       (c-decl-1 (cadr type)
		 (c-append "((" expr ")[1])")))
      ((function)
       (c-decl-1 (cadr type) 
		 (c-append expr "(" (c-list "," (cddr type)) ")")))
      ((const)
       (c-append "const" (c-decl-1 (cdr type) expr)))
      (else (error "c-decl: Invalid type " type))))
  (c-decl-1 (var-type var) (var-name var)))

(define (c-struct name vars)
  (c-append "struct " name indent
	    (c-block (map c-declare vars))
	    ";" indent))

(define (type->category type)
  (if (atom? type)
      (type->category `(simple ,type))
      (let ((tag (car type)))
	(case tag
	  ((string object simple special indirect-special
	    bignum struct) tag)
	  ((const) (type->category (cdr type)))
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
	((const) `("const " ,(type->declaration (cdr type) expr)))
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
	((const) (type->mark (cdr type) expr))
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
	((const) (type->free (cdr type) expr))
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

; New version
(define (make-instance-struct name super vars)
  (c-struct name (cons `(super struct ,(or super "lsh_object"))
		       vars)))

; For counter variables
(define make-var
  (let ((*count* 0))
    (lambda ()
      (set! *count* (+ 1 *count*))
      (c-append "k" *count*))))

; Invokes f on type and expression for each variable.
(define (map-variables f vars pointer)
  (filter identity (map (lambda (var)
			  (f (var-type var)
			     (c-append pointer "->" (var-name var))))
			vars)))

(define (make-marker type expr)
  (case (car type)
    ((string simple function bignum) #f)
    ((object) (c-call "mark" (c-append "(struct lsh_object *) " expr)))
    ((struct) (c-call (c-append (cadr type) "_mark")
		      (c-address expr)
		      "mark"))
    ((pointer space)
     (if (null? (cddr type))
	 (make-marker (cadr type)
		      (c-append "*(" expr ")"))
	 ;; The optional argument should be the name of
	 ;; an instance variable holding the length of
	 ;; the area pointed to.
	 (let* ((counter (make-var))
		(mark-k (make-marker (cadr type)
				     (c-append "(" expr ")[" counter "]"))))
	   (and mark-k
		(c-block* (c-declare `( ,counter simple unsigned))
			  (c-for counter (c-append "i->" (caddr type))
				 mark-k))))))
    ((special)
     (let ((mark-fn (caddr type)))
       (and mark-fn (c-call mark-fn expr "mark"))))
      
    ((indirect-special)
     (let ((mark-fn (caddr type)))
       (and mark-fn (c-call mark-fn
			    (c-address expr)
			    "mark"))))
    ((array)
     (let* ((counter (make-var))
	    (mark-k (make-marker (cadr type)
				 (c-append "(" expr ")[" counter "]"))))
       (and mark-k
	    (c-block* (c-declare `( ,counter simple unsigned))
		      (c-for counter (caddr type)
			     mark-k)))))
    ((var-array)
     (let* ((counter (make-var))
	    (mark-k (make-marker (cadr type)
				 (c-append "(" expr ")[" counter "]"))))
       (and mark-k
	    (c-block* (c-declare `( ,counter simple unsigned))
		      (c-for counter (c-append "i->" (caddr type))
			     mark-k)))))
    ((const) (make-marker (cdr type) expr))
    (else (error "make-marker: Invalid type " type))))

(define (make-mark-function name vars)
  (let ((markers (map-variables make-marker vars "i")))
    (and (not (null? markers))
	 (c-append (c-prototype "static void" (c-append "do_" name "_mark")
				"struct lsh_object *o"
				"void (*mark)(struct lsh_object *o)")
		   indent
		   (c-block (cons (c-append "struct " name
					    " *i = (struct " name " *) o;")
				  markers))
		   indent))))

(define (make-freer type expr)
  (case (car type)
    ((object simple function pointer) #f)
    ((struct) (c-call (c-append (cadr type) "_free") (c-address expr)))
    ((string) (c-call "lsh_string_free" expr))
    ((bignum) (c-call "mpz_clear" expr))
    ((space) (c-call "lsh_space_free" expr))
    ((special) (c-call (cadddr type) expr))
    ((indirect-special)
     (let ((free (cadddr type)))
       (and free (c-call free (c-address expr)))))
    ((array)
     (let* ((counter (make-var))
	    (free-k (make-freer (cadr type)
				(c-append "(" expr ")[" counter "]"))))
       (and free-k
	    (c-block* (c-declare `( ,counter simple unsigned))
		      (c-for counter (caddr type)
			     free-k)))))

    ((var-array)
     (let* ((counter (make-var))
	    (free-k (make-freer (cadr type)
				(c-append "(" expr ")[" counter "]"))))
       (and free-k
	    (c-block* (c-declare `( ,counter simple unsigned))
		      (c-for counter (c-append "i->" (caddr type))
			     free-k)))))
    ((const) (make-freer (cdr type) expr))
    (else (error "make-freer: Invalid type " type))))

(define (make-free-function name vars)
  (let ((freers (map-variables make-freer vars "i")))
    (and (not (null? freers))
	 (c-append (c-prototype "static void" (c-append "do_" name "_free")
				"struct lsh_object *o)")
		   (c-block (cons (c-append "struct " name
					    " *i = (struct " name " *) o;")
				  freers))
		   indent))))
	 
(define (struct-mark-prototype name)
  (c-append "void " name "_mark(struct " name " *i,\n"
	    " void (*mark)(struct lsh_object *o))"))

(define (struct-mark-function name vars)
  (c-append (struct-mark-prototype name) indent
	    (c-block
	     ;; To avoid warnings for unused parameters
	     (cons "(void) mark; (void) i;"
		   (map-variables make-marker vars "i")))))

(define (struct-free-prototype name)
  (c-append "void " name "_free(struct " name " *i)"))

(define (struct-free-function name vars)
  (c-append (struct-mark-prototype name) indent
	    (c-block
	     ;; To avoid warnings for unused parameters
	     (cons "(void) mark; (void) i;"
		   (map-variables make-freer vars "i")))))

(define (make-class name super mark free meta methods)
  (let ((initializer
	 (c-initializer*
	  "STATIC_HEADER"
	  (if super
	      ;; FIXME: A cast (struct lsh_class *) or something
	      ;; equivalent is needed if the super class is not a
	      ;; struct lsh_class *. For now, fixed with macros
	      ;; expanding to the right component of extended class
	      ;; structures.
	      (c-address (c-append super "_class"))
	      "NULL")
	  (c-string name)
	  (c-call "sizeof" (c-append "struct " name))
	  (if mark (c-append "do_" name "_mark") "NULL")
	  (if free (c-append "do_" name "_free") "NULL"))))
    (if meta
	(c-append "struct " meta "_meta "name "_class_extended ="
		  indent
		  (c-initializer (cons initializer (or methods '())))
		  ";" indent)
	(c-append "struct lsh_class " name "_class ="
		  indent initializer ";" indent))))

(define (make-meta name methods)
  (c-append "struct " name "_meta" indent
	    (c-block methods) ";" indent)) 

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

(define (preprocess name vars)
  (define (preprocess-type type)
    (if (atom? type)
	`(simple ,type)
	(case (car type)
	  ;; Primitive types
	  ((string object bignum simple special indirect-special struct)
	   type)
	  ;; Second element is a type
	  ((array var-array pointer space function)
	   `( ,(car type) ,(preprocess-type (cadr type)) ,@(cddr type)))
	  ;; Tail is a type
	  ((const)
	   (cons 'const (preprocess-type (cdr type))))
	  ;; Shorthands
	  ((method)
	   `(pointer (function ,(preprocess-type (cadr type))
			       ("struct " ,name " *self")
			       ,@(cddr type)))))
	((indirect-method)
	 `(pointer (function ,(preprocess-type (cadr type))
			     ("struct " ,name " **self")
			     ,@(cddr type))))
	(else (error "preprocess-type: Invalid type " type))))

  (map (lambda (var)
	 (cons (var-name var) (preprocess-type (var-type var))))
       vars))

(define (class-annotate name super meta)
  (c-append "/*\nCLASS:" name ":" (or super "")
	    (if meta (list ":" meta "_meta") "") "\n*/\n"))

(define (process-class attributes)
  (let ((name (get 'name attributes cadr))
	(super (get 'super attributes cadr))
	(raw-vars (get 'vars attributes cdr))
	(meta (get 'meta attributes cadr))
	(methods (get 'methods attributes cdr)))
    (werror "Processing class ~S\n" name)
    ; (werror "foo\n")
    (let ((vars (preprocess name raw-vars)))
      (let ((mark-function (make-mark-function name vars))
	    (free-function (make-free-function name vars)))
	; (werror "baar\n")
	(c-append (class-annotate name super meta)
		  "#ifndef GABA_DEFINE\n"	
		  (make-instance-struct name super vars)
		  (if meta
		      (c-append "extern struct " meta "_meta "
				name "_class_extended;\n"
				"#define " name "_class (" name
				"_class_extended.super)\n")
		      (c-append "extern struct lsh_class " name "_class;\n"))
		  "#endif /* !GABA_DEFINE */\n\n"
		  "#ifndef GABA_DECLARE\n"
		  (or mark-function "")
		  (or free-function "")
		  (make-class name super mark-function free-function
			      meta methods)
		  "#endif /* !GABA_DECLARE */\n\n")))))

(define (process-meta attributes)
  (let ((name (get 'name attributes cadr))
	(methods (get 'methods attributes cdr)))
    (werror "Processing meta ~S\n" name)
    (c-append "#ifndef GABA_DEFINE\n"
	      (make-meta name methods)"struct " name "_meta\n"
	      "#endif /* !GABA_DEFINE */"
	      indent)))

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
    (let ((vars (preprocess name raw-vars)))
      ; (werror "baar\n")
      (c-append "#ifndef GABA_DEFINE\n"	
		(c-struct name vars)
		"extern " (struct-mark-prototype name) ";\n"
		"extern " (struct-free-prototype name) ";\n"
		"#endif /* !GABA_DEFINE */\n\n"
		"#ifndef GABA_DECLARE\n"
		(struct-mark-function name vars)
		(struct-free-function name vars)
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
      ;; (werror "Globals: ~S\n" globals)
      ;; (werror "Params: ~S\n" params)
      (c-append (c-prototype "static struct lsh_object *" name
			     (if params (declare-params params) "void"))
		indent "{\n"
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
	      (out 0 (process-input exp))
	      (main)))))))

; (main)
