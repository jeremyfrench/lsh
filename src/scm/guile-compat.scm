;; guile.scm
;;
;; Extra definitions needed when using guile .
;;
;; $Id$

;; lsh, an implementation of the ssh protocol
;;
;; Copyright (C) 1999 Tommy Virtanen, Niels Möller
;;
;; This program is free software; you can redistribute it and/or
;; modify it under the terms of the GNU General Public License as
;; published by the Free Software Foundation; either version 2 of the
;; License, or (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
;; General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program; if not, write to the Free Software
;; Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

(use-modules (ice-9 slib))
(require 'macro-by-example)
(require 'format)

(define error-output-port current-error-port)
(define ascii->char integer->char)
(define char->ascii char->integer)
(define write-string display)

;; Implementation of the charset abstraction
(define (is-in-charset? set n)
  (not (zero? (char->integer (string-ref set n)))))

(define (char-set-members char-set)
  (define (helper n)
    (cond ((>= n 256) '())
          ((is-in-charset? char-set n) (cons (integer->char n)
                                             (helper (1+ n))))
          (else (helper (1+ n)))))
  (helper 0))

(define (ascii-range->char-set lower upper)
  (do ((result (make-string 256 (integer->char 0)))
       (i lower (+ i 1)))
      ((= i upper) result)
    (string-set! result i (integer->char 1))))

(define (chars->char-set chars)
  (do ((result (make-string 256 (integer->char 0)))
       (chars chars (cdr chars)))
      ((null? chars) result)
    (string-set! result (char->integer (car chars)) (integer->char 1))))

(define (string->char-set str)
  (chars->char-set (string->list str)))

(define (char-set-intersection set1 set2)
  (do ((result (make-string 256))
       (i 0 (+ i 1)))
      ((= i 255) result)
    (string-set! result i 
                 (if (and (is-in-charset? set1 i) (is-in-charset? set2 i))
                     (integer->char 1)
                     (integer->char 0)))))

(define (char-set-union set1 set2)
  (do ((result (make-string 256))
       (i 0 (+ i 1)))
      ((= i 255) result)
    (string-set! result i 
                 (if (or (is-in-charset? set1 i) (is-in-charset? set2 i))
                     (integer->char 1)
                     (integer->char 0)))))

(define (char-set-difference set1 set2)
  (do ((result (make-string 256))
       (i 0 (+ i 1)))
      ((= i 255) result)
    (string-set! result i 
                 (if (and (is-in-charset? set1 i) 
                          (not (is-in-charset? set2 i)))
                     (integer->char 1)
                     (integer->char 0)))))

(define char-set= string=?)

(define char-set:empty (chars->char-set '()))

(define (nth l n)
  (cond ((< n 0) (error "nth: negative index not allowed" n))
        ((null? l) (error "nth: index too big" n))
        ((= n 0) (car l))
        (else (nth (cdr l) (-1+ n)))))

