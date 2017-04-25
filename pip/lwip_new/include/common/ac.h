/* * Portable Integrity Protection (PIP) System -
 * Copyright (C) 2012 Secure Systems Laboratory, Stony Brook University
 *
 * This file is part of Portable Integrity Protection (PIP) System.
 *
 * Portable Integrity Protection (PIP) System is free software: you can redistribute it
 * and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Portable Integrity Protection (PIP) System is distributed in the hope that it will
 * be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portable Integrity Protection (PIP) System.  If not, see
 * <http://www.gnu.org/licenses/>.
 */


#ifndef _AC_H_
#define _AC_H_

typedef struct actreenode {
  char ch;
  int matchid;
  struct actreenode *outlink, *faillink;
  struct actreenode *children, *sibling;
} ACTREE_NODE, *AC_TREE;


typedef struct {
  AC_TREE tree;
  int ispreprocessed, errorflag;

  int Psize;
  int *Plengths;

  char *T;
  int N, c, initflag, endflag;
  AC_TREE w, output;

  int prep_new_edges, prep_old_edges, prep_fail_compares;
  int num_compares, num_failures, edges_traversed, outlinks_traversed;
} AC_STRUCT;


AC_STRUCT *ac_alloc(void);
int ac_add_string(AC_STRUCT *node, char *P, int M, int id);
int ac_del_string(AC_STRUCT *node, char *P, int M, int id);
int ac_prep(AC_STRUCT *node);
void ac_search_init(AC_STRUCT *node, char *T, int N);
char *ac_search(AC_STRUCT *node, int *length_out, int *id_out);
void ac_free(AC_STRUCT *node);

#endif
