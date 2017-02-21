// CS 153: Introduction to Computer Security
// Machine Problem #1: SmallDES (Breaker)
// MANALO, Juan Miguel C.
// 2014-40093

/*
	Modifications:
	1. Two IP Values changed
	2. S-Box Sequence changed
	3. Two P-Box Values changed
	4. Two Inv. IP Values changed
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Node
{
	int bit;
	struct Node *next;
	struct Node *prev;
};

struct List
{
	struct Node *front;
	struct Node *rear;
	int size;
};

void initNode(struct Node*);
void initList(struct List*);
void insertList(struct List*, int);
void editList(struct List*, int, int);
int getListElem(struct List*, int);
void printList(struct List*);
void deleteList(struct List*);
int roundFunc(struct List*, struct List*, int);

int main(void)
{
	FILE *Fi, Fo;
	Fi = fopen("sample2.txt", "r");
	char S[32], SN[12], plain[20];
	int i, j;
	int perm[16] = {8, 11, 2, 3, 4, 9, 15, 13, 5, 1, 6, 16, 7, 12, 14, 10};
	int inv_perm[16] = {10, 3, 4, 5, 9, 11, 13, 1, 6, 16, 2, 14, 8, 15, 7, 12};
	int key2[4][16] =	{{1, 2, 3, 1, 4, 5, 6, 2, 7, 8, 9, 3, 10, 11, 12, 4},
						{1, 2, 3, 2, 4, 5, 6, 4, 7, 8, 9, 6, 10, 11, 12, 8},
						{1, 2, 3, 3, 4, 5, 6, 6, 7, 8, 9, 9, 10, 11, 12, 12},
						{1, 2, 3, 4, 4, 5, 6, 8, 7, 8, 9, 12, 10, 11, 12, 4}};
	struct List *outputL = (struct List*)malloc(sizeof(struct List));
	initList(outputL);
	struct List *outputR = (struct List*)malloc(sizeof(struct List));
	initList(outputR);
	struct List *temp = (struct List*)malloc(sizeof(struct List));
	initList(temp);
	struct List *temp2 = (struct List*)malloc(sizeof(struct List));
	initList(temp2);
	struct List *key = (struct List*)malloc(sizeof(struct List));
	initList(key);
	struct List *subkey = (struct List*)malloc(sizeof(struct List));
	initList(subkey);
	struct List *input = (struct List*)malloc(sizeof(struct List));
	initList(input);
	
	fscanf(Fi, "%s", S);
	fscanf(Fi, "%s", S);
	
	// Student No.
	fscanf(Fi, "%s", S);
	strcpy(SN, S);
	
	fscanf(Fi, "%s", S);
	
	// Input
	fscanf(Fi, "%s", S);
	strcpy(plain, S);
		
	fscanf(Fi, "%s", S);
	
	// Key
	fscanf(Fi, "%s", S);
	for (i = 0; i < 12; i++)
		insertList(key, (int)S[i]-48);
		
	fscanf(Fi, "%s", S);
	
	// Output
	fscanf(Fi, "%s", S);
	printf("Ciphertext: %s\n\n", S);
	
	for (i = 0; i < 8; i++)
	{
		insertList(outputL, (int)S[inv_perm[i]-1]-48);
		insertList(outputR, (int)S[inv_perm[i+8]-1]-48);
		insertList(temp, 0);
		insertList(temp2, 0);
	}
	printf("Init Perm:  "); printList(outputL);
	printf("                    "); printList(outputR);

	for (i = 0; i < 4; i++)
	{
		printf("L%i: ", 4-i); printList(outputL);
		printf("R%i: ", 4-i); printList(outputR);
		for (j = 0; j < 16; j++)
			insertList(subkey, getListElem(key, key2[3-i][j]-1));
		printf("RF: ");
		for (j = 0; j < 8; j++)
		{
			editList(temp2, j, getListElem(outputL, j));
			editList(temp, j, (getListElem(outputR, j)+roundFunc(outputL, subkey, j))%2);
			printf("%i", roundFunc(outputL, subkey, j));
		}
		printf("\n");
		for (j = 0; j < 8; j++)
		{
			editList(outputL, j, getListElem(temp, j));
			editList(outputR, j, getListElem(temp2, j));
		}
		printf("L%i: ", 3-i); printList(outputL);
		printf("R%i: ", 3-i); printList(outputR);
		printf("K%i: ", 4-i); printList(subkey);
		printf("\n");
		deleteList(subkey);
		initList(subkey);
	}
	
	for (i = 0; i < 16; i++)
	{
		if (perm[i] <= 8)
			insertList(input, getListElem(outputL, perm[i]-1));
		else
			insertList(input, getListElem(outputR, (perm[i]-1)%8));
	}
	printf("Key:       "); printList(key);
	printf("Plaintext: "); printList(input);
	
	printf("CorrectIn: %s\n", plain);
	
	deleteList(outputL);
	deleteList(outputR);
	deleteList(temp);
	deleteList(temp2);
	deleteList(key);
	deleteList(input);
	free(outputL);
	free(outputR);
	free(temp);
	free(temp2);
	free(key);
	free(subkey);
	free(input);
	
	fflush(Fi);
	fclose(Fi);
	return 0;
}

int roundFunc(struct List *L, struct List *K, int ind)
{
	int i, j, retval;
	char c;
	char S_Box[4][4][4][5] = {{{"0000", "0001", "0010", "0011"},
							{"0100", "0101", "0110", "0111"},
							{"1000", "1001", "1010", "1011"},
							{"1100", "1101", "1110", "1111"}},
							{{"0000", "1000", "0001", "1001"},
							{"0100", "1100", "0100", "1100"},
							{"0010", "1010", "1010", "1011"},
							{"0110", "1100", "0111", "1111"}},
							{{"0000", "0100", "0010", "0110"},
							{"0001", "0101", "0011", "0111"},
							{"1000", "1100", "1010", "1110"},
							{"1001", "1101", "1011", "1111"}},
							{{"0000", "0100", "0010", "0110"},
							{"1000", "1010", "1100", "1110"},
							{"0001", "0011", "0101", "0111"},
							{"1001", "1011", "1101", "1111"}}};
	int perm[8] = {3, 5, 8, 6, 2, 4, 1, 7};
	struct List *temp = (struct List*)malloc(sizeof(struct List));
	initList(temp);
	struct List *exp;
	exp = (struct List*)malloc(sizeof(struct List));
	initList(exp);
	for (i = 0; i < 4; i++)
	{
		// STEP 5a-b
		for (j = 0; j < 4; j++)
		{
			insertList(exp, getListElem(L, (i*2+j+7)%8));
			editList(exp, j, (getListElem(exp, j)+getListElem(K, i*4+j))%2);
		}
		// STEP 5a-b
		
		// STEP 5c-e
		c = S_Box[i][(getListElem(exp, 0))*2 + (getListElem(exp, 3))][(getListElem(exp, 1))*2 + (getListElem(exp, 2))][1];
		insertList(temp, (int)c-48);
		c = S_Box[i][(getListElem(exp, 0))*2 + (getListElem(exp, 3))][(getListElem(exp, 1))*2 + (getListElem(exp, 2))][2];
		insertList(temp, (int)c-48);
		// STEP 5c-e
		deleteList(exp);
		initList(exp);
	}
	deleteList(exp);
	free(exp);
	retval = getListElem(temp, perm[ind]-1);
	deleteList(temp);
	free(temp);
	return retval;
}

void initNode(struct Node *n)
{
	n->bit = 0;
	n->next = NULL;
	n->prev = NULL;
}

void initList(struct List *list)
{
	list->front = NULL;
	list->rear = NULL;
	list->size = 0;
}

void insertList(struct List *list, int bit)
{
	struct Node *n = (struct Node*)malloc(sizeof(struct Node));
	initNode(n);
	n->bit = bit;
	if (list->size == 0)
		list->front = list->rear = n;
	else
	{
		list->rear->next = n;
		n->prev = list->rear;
		list->rear = n;
	}
	list->size++;
}

void editList(struct List *list, int ind, int bit)
{
	struct Node *n = list->front;
	int i = 0;
	while (i < ind)
	{
		n = n->next;
		i++;
	}
	n->bit = bit;
}

int getListElem(struct List *list, int ind)
{
	struct Node *n = list->front;
	int i = 0;
	while (i < ind)
	{
		n = n->next;
		i++;
	}
	return n->bit;
}

void printList(struct List *list)
{
	struct Node *n = list->front;
	while (n != NULL)
	{
		printf("%i", n->bit);
		n = n->next;
	}
	printf("\n");
}

void deleteList(struct List *L)
{
	struct Node *n = L->front;
	while (n != NULL)
	{
		L->front = L->front->next;
		free(n);
		n = L->front;
	}
}