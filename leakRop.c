#include <stdio.h>
#include <stdlib.h>

int main()
{
	char name[32];
	puts("Welcome to the No Security Aggregate");
	puts("Please sign in with your name.");
	printf("By the way, I found this on the floor, is it yours? %p\n", **(int**)*(puts+2));
	gets(name);
	printf("Please take a seat, we'll be with you at some point this week.\n");
	return 0;
}
