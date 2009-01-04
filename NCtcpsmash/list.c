#include "nctcpsmash.h"

int Head (list l)  {
	return l->num;
}

list Tail (list l)  {
	return l->next;
}

list Insert (int val, list l)  {
	list t = (list) malloc(sizeof(node));

	t->num  = val;
	t->next = l;
	return t;
}

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

