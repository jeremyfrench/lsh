;; make-char-classes.scm
;;
;; Run with
;;   $ scsh -e main -l scsh-compat.scm -s make-char-classes.scm
;;   $ guile -e main -l guile-compat.scm -s make-char-classes.scm

;; Reads an alist of character classes and their contents,
;; computes a partition of disjunct sets, associate a bit with each
;; partition set, and finally writes a C file containing
;; a partition table index by character, and masks corresponding to
;; the input classes.

;; Misc functions
(define (my-error s . args)
  (error (apply format #f s args)))

(define (debug s . args)
  ; (apply format (error-output-port) s args))
  #f)

(define (werror s . args)
  (apply format (error-output-port) s args))

(define (filter p l)
  (cond ((null? l) l)
	((p (car l))
	 (cons (car l) (filter p (cdr l))))
	(else (filter p (cdr l)))))

(define (identity x) x)

(define (invert-predicate p)
  (lambda (x) (not (p x))))

(define (reduce op start l)
  (if (null? l)
      start
      (reduce op (op start (car l)) (cdr l))))

(define (subvector v start end)
  (let ((n (make-vector (- end start))))
    (let loop ((i start))
      (when (< i end)
	    (vector-set! n (- i start) (vector-ref v i))
	    (loop (+ i 1))))
    n))

(define (vector-split v n)
  (let ((parts (make-vector n))
	(length (quotient (+ (vector-length v) n -1) n)))
    (let loop ((i 0) (start 0))
      (cond  ((= i (- n 1))
	      (vector-set! parts i (subvector v start (vector-length v))))
	     (else
	      (vector-set! parts i (subvector v start (+ start length)))
	      (loop (+ i 1) (+ start length)))))
    parts))

(define (implode separator list)
  (cond ((null? list) "")
	((null? (cdr list)) (car list))
	(else
	 (string-append (car list) separator (implode separator (cdr list))))))

(define-syntax when
  (syntax-rules () ((when test . consequences) (if test (begin . consequences)))))

;; A little more user-friendly input format.
(define (input->char-set o names)
  (define (->ascii x)
    (cond ((integer? x) x)
	  ((char? x) (char->ascii x))
	  (else #f)))
  (define (->char x)
    (cond ((integer? x) (ascii->char x))
	  ((char? x) x)
	  (else #f)))
  (define (integer-or-char? x)
    (or (integer? x) (char? x)))

  (cond ((string? o)
	 (string->char-set o))
	((symbol? o)
	 (cdr (assq o names)))
	((and (pair? o) (not (pair? (cdr o))))
	 (ascii-range->char-set (->ascii (car o))
				(+ 1 (->ascii (cdr o)))))
	((list? o)
	 (reduce char-set-union (chars->char-set
				 (map ->char (filter integer-or-char? o)))
		 (map (lambda (o) (input->char-set o names))
		      (filter (invert-predicate integer-or-char?) o))))
	(else (my-error "Bad char set specification ~s" o))))

;; Depends on charsets implemented as strings
(define char-set=? string=?)

(define char-set-empty?
  (let ((empty (chars->char-set '())))
    (lambda (o) (char-set=? o empty))))

(define char-set-assoc assoc)

;; We use an acyclic graph, where the input char-sets are used as
;; roots, and two intersecting nodes will branch into three childen,
;; one of which is shared. The children of each node are disjunct.
;;
;;   ABC    BCD
;;  /   \  /   \
;;  A    BC     D

(define (make-tree set)
  ;; Fields are set, leafness, left and right child (if any) and indexnumber.
  (vector set #t #f #f #f))

(define (tree/set tree)
  (vector-ref tree 0))

(define (tree/leaf? tree)
  (vector-ref tree 1))

(define (tree/left tree)
  (vector-ref tree 2))

(define (tree/right tree)
  (vector-ref tree 3))

(define (tree/split! tree left right)
  (cond ((tree/leaf? tree)
	 (vector-set! tree 1 #f)
	 (vector-set! tree 2 left)
	 (vector-set! tree 3 right))
	(else (my-error "Attempt to split non-leaf"))))

(define (tree/index tree)
  (vector-ref tree 4))

(define (tree/index! tree n)
  (vector-set! tree 4  n))

(define (tree-describe tree)
  (if (tree/leaf? tree)
      (list 'leaf
	    (tree/index tree)
	    (char-set-members (tree/set tree)))
      (list 'node
	    (char-set-members (tree/set tree))
	    (tree-describe (tree/left tree))
	    (tree-describe (tree/right tree))	    )))

(define (make-tree-cache initial)
  (let ((cache (map (lambda (tree) (cons (tree/set tree) tree))
		    initial)))
    (lambda (set)
      (debug "cache: ~s\n" (map (lambda (pair) (char-set-members (car pair)))
				   cache))
      (cond ((char-set-assoc set cache)
	     => cdr)
	    (else
	     (let ((new (make-tree set)))
	       (debug "Adding set ~s\n" (char-set-members set))
	       (set! cache (cons (cons set new) cache))
	       new))))))


(define (for-children f tree)
  (f (tree/left tree))
  (f (tree/right tree)))
  
;; Iterate over all leafs
(define (for-leafs f tree)
  (if (tree/leaf? tree)
      (f tree)
      (for-children (lambda (c) (for-leafs f c)) tree)))

(define (map-leafs f tree)
  (if (tree/leaf? tree)
      (list (f tree))
      (append (map-leafs f (tree/left tree))
	      (map-leafs f (tree/right tree)))))

;; Destructivly intersect the leafs of two trees
(define (tree-intersect! cache t1 t2)
  (if (not (eq? t1 t2))
      (let* ((s1 (tree/set t1))
	     (s2 (tree/set t2))
	     (intersection (char-set-intersection s1 s2)))
	(if (not (char-set-empty? intersection))
	    (if (tree/leaf? t1)
		(if (tree/leaf? t2)
		    (let ((diff1 (char-set-difference s1 s2))
			  (diff2 (char-set-difference s2 s1)))
		      (define (split-subset! super sub diff)
			(tree/split! super sub (cache diff)))
		      (if (char-set-empty? diff1)
			  (if (char-set-empty? diff2)
			      (my-error "Two copies of ~s ~s"
				     (tree-describe t1)
				     (tree-describe t2))
			      ; t1 is a subset of t2, so we need only split t2
			      (split-subset! t2 t1 diff2))
			  (if (char-set-empty? diff2)
			      ; t2 is a subset of t1, so split t1
			      (split-subset! t1 t2 diff1)
			      ; Both differences ar non-empty, so split both
			      (let ((common (cache intersection)))
				(tree/split! t1 common (cache diff1))
			    (tree/split! t2 common (cache diff2))))))
		    ; t1 is a leaf, but not t2. Recurse.
		    (for-children (lambda (c)
				    (tree-intersect! cache t1 c))
				  t2))
		; t1 is a non-leaf
		(for-children (lambda (c)
				(tree-intersect! cache t2 c))
			      t1))))))

(define (partition! sets)
  (let ((cache (make-tree-cache sets)))
    (let loop ((left sets))
      (let ((head (car left))
	    (tail (cdr left)))
	(when (not (null? tail))
	      (for-each (lambda (tree) (tree-intersect! cache head tree))
			tail)
	      (loop tail))))))

(define (index-leafs! roots)
  (let ((index 1)
	(leafs '()))
    (for-each (lambda (tree)
		(for-leafs (lambda (leaf)
			     (when (not (tree/index leaf))
				   (tree/index! leaf index)
				   (set! index (+ 1 index))
				   (set! leafs (cons leaf leafs))))
			   tree))
	      roots)
    leafs))

(define (build-char-table leafs)
  (let ((table (make-vector #x100 0)))
    (for-each (lambda (leaf)
		(let ((flag (tree/index leaf)))
		  (for-each (lambda (c)
			      (vector-set! table (char->ascii c) flag))
			    (char-set-members (tree/set leaf)))))
	      leafs)
    table))

(define (build-flags root)
  (map-leafs tree/index root))

(define (prepare-input l)
  (let loop ((left l) (out '()) (names '()))
    (if (null? left)
	out
	(let* ((name (caar left))
	       (input (cdar left))
	       (set (input->char-set input
				     names)))
	  (werror "Read class ~a\n" name)
	  (loop (cdr left)
		(cons (cons name
			    (make-tree set))
		      out)
		(cons (cons name set) names))))))

#!
(define test-input
  '((alpha . ( (#\a . #\z) (#\A . #\Z) ))
    (digits . ( (#\0 . #\9)))
    (base64 . ( (#\a . #\z) (#\A . #\Z) (#\0 . #\9) #\+ #\/ #\=))
    (hex . ( (#\0 . #\9) (#\a . #\f) (#\A . #\F) ))))

(define (test1)
  (let* ((input (prepare-input test-input))
	 (roots (map cdr input)))
    (partition! roots)
    (let ((leafs (index-leafs! roots)))
      (werror "~s disjunct classes found." (length leafs))
      (build-char-table leafs))))
!#

(define (bit->mask bit)
  (format #f "1L<<~s" bit))

(define (make-char-classes input)
  (let* ((classes (prepare-input input))
	 (roots (map cdr classes)))
    (partition! roots)

    (write-string "#ifdef CHAR_CLASSES_TABLE\n")
    (write-string "int CHAR_CLASSES_TABLE[] =\n")

    (let ((leafs (index-leafs! roots)))
      (werror "~s disjunct classes found.\n" (length leafs))
      (format #t
	      "{\n  ~a\n};\n"
	      (implode ",\n  "
		       (map (lambda (row)
			      (implode ", " (map bit->mask
						 (vector->list row))))
			    (vector->list (vector-split (build-char-table leafs)
							32))))))
    (write-string "#else /* !CHAR_CLASSES_TABLE */\n")
    (for-each (lambda (class)
		(format #t "#define CHAR_~a (~a)\n"
			(car class)
			(implode " | " (map bit->mask (build-flags (cdr class))))))
	      classes)
    (write-string "#define CHAR_other 1\n")
    (write-string "#endif /* !CHAR_CLASSES_TABLE */\n")))

(define test-2-input
  '((lower . "abcdefghijklmnopqrstuvwxyz")
    (upper . "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    (alpha . (lower upper))
    (digits . "0123456789")
    (hex . (digits "abcdefABCDEF"))
    ;; base 64 digits, including the '=' pad character
    (base64 . (alpha digits "+/="))
    (control . ( (0 . #x1f) (#x80 . #x9f) #x7f))
    ;; SPC, TAB, LF, CR
    (space . (#x20 #x9 #xa #xd))
    ;; \b \t \n \v \f \r
    (escapable . (#x8 #x9 #xa #xb #xc #xd))
    (punctuation . "-./_:*+=")
    ;; Characters defined by most iso-8859-1 character sets
    (international . (#xa0 . #xff))))

(define (test-2)
  (make-char-classes test-2-input))

(define (main . ignored)
  (make-char-classes (read)))
