/*
 * NCtcpsmash/list.c
 *
 * (C) 2007,2009, BlackLight <blacklight@autistici.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */

#include "nctcpsmash.h"

/**
 * @brief It returns a list's head
 * @param l List
 * @return l's head
 */
int Head (list l)  {
	return l->num;
}

/**
 * @brief It returns a list's tail
 * @param l List
 * @return l's tail
 */
list Tail (list l)  {
	return l->next;
}

/**
 * @brief It inserts a new value in a list
 * @param val Value to insert
 * @param l List
 * @return List after insert
 */
list Insert (int val, list l)  {
	list t = (list) GC_MALLOC(sizeof(node));

	t->num  = val;
	t->next = l;
	return t;
}

/**
 * @brief It checks if a list contains a given element
 * @param val Element
 * @param l List
 * @return 1 if val IN l, 0 if val NOT IN l
 */
int Contains (int val, list l)  {
	list t;
	t = Insert (Head(l), Tail(l));

	while (t)  {
		if (Head(t) == val)
			return 1;

		t = Tail(t);
	}

	return 0;
}

