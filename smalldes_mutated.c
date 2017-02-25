// CS 153: Introduction to Computer Security
// Machine Problem #1: SmallDES
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
int matchResult(struct List*, char[]);
int roundFunc(struct List*, struct List*, int, int, int, int);
int getPermInd(int, int[]);

int main(void)
{
	FILE *Fi, Fo;
	Fi = fopen("sample2.txt", "r");
	char S[32], SN[12], plain[18], cipher[18], k[16];
	int i, j, S_P, IP_i, IP_j, P_i, P_j, swap, flag = 0, cases = 0;
	int perm[16] = {10, 3, 4, 5, 9, 11, 13, 1, 6, 16, 2, 14, 8, 15, 7, 12};
	int inv_perm[16] = {8, 11, 2, 3, 4, 9, 15, 13, 5, 1, 6, 16, 7, 12, 14, 10};
	int key2[4][16] =	{{1, 2, 3, 1, 4, 5, 6, 2, 7, 8, 9, 3, 10, 11, 12, 4},
						{1, 2, 3, 2, 4, 5, 6, 4, 7, 8, 9, 6, 10, 11, 12, 8},
						{1, 2, 3, 3, 4, 5, 6, 6, 7, 8, 9, 9, 10, 11, 12, 12},
						{1, 2, 3, 4, 4, 5, 6, 8, 7, 8, 9, 12, 10, 11, 12, 4}};
	struct List *inputL = (struct List*)malloc(sizeof(struct List));
	struct List *inputR = (struct List*)malloc(sizeof(struct List));
	struct List *temp = (struct List*)malloc(sizeof(struct List));
	struct List *temp2 = (struct List*)malloc(sizeof(struct List));
	struct List *key = (struct List*)malloc(sizeof(struct List));
	struct List *subkey = (struct List*)malloc(sizeof(struct List));
	struct List *output = (struct List*)malloc(sizeof(struct List));
	
	fscanf(Fi, "%s", S);
	fscanf(Fi, "%s", S);
	
	for (cases = 0; cases < 3; cases++)
	{
		flag = 0;
		// Student No.
		fscanf(Fi, "%s", S);
		strcpy(SN, S);
		
		fscanf(Fi, "%s", S);
		
		/** STEP 1-3 **/
		// Input
		fscanf(Fi, "%s", S);
		strcpy(plain, S);
		
		fscanf(Fi, "%s", S);
		
		// Key
		fscanf(Fi, "%s", S);
		strcpy(k, S);
		
		fscanf(Fi, "%s", S);
		
		// Output
		fscanf(Fi, "%s", S);
		strcpy(cipher, S);
		/** STEP 1-3 **/
		
		for (IP_i = 0; IP_i < 15; IP_i++)
		{
			for (IP_j = IP_i+1; IP_j < 16; IP_j++)
			{
				printf("[%i, %i]\n", IP_i, IP_j);
				for (P_i = 0; P_i < 7; P_i++)
				{
					for (P_j = P_i+1; P_j < 8; P_j++)
					{
						//printf("[%i, %i, %i, %i]\n", IP_i, IP_j, P_i, P_j);
						for (S_P = 0; S_P < 256; S_P++)
						{
							initList(inputL);
							initList(inputR);
							initList(temp);
							initList(temp2);
							initList(key);
							initList(subkey);
							initList(output);
							for (i = 0; i < 8; i++)
							{
								insertList(inputL, (int)plain[perm[i]-1]-48);
								insertList(inputR, (int)plain[perm[i+8]-1]-48);
								insertList(temp, 0);
								insertList(temp2, 0);
							}
							if ((IP_i < 8) && (IP_j < 8))
							{
								swap = getListElem(inputL, IP_i);
								editList(inputL, IP_i, getListElem(inputL, IP_j));
								editList(inputL, IP_j, swap);
							}
							else if ((IP_i < 8) && (IP_j >= 8))
							{
								swap = getListElem(inputL, IP_i);
								editList(inputL, IP_i, getListElem(inputR, IP_j%8));
								editList(inputR, IP_j%8, swap);
							}
							else if ((IP_i >= 8) && (IP_j >= 8))
							{
								swap = getListElem(inputR, IP_i%8);
								editList(inputR, IP_i%8, getListElem(inputR, IP_j%8));
								editList(inputR, IP_j%8, swap);
							}
							for (i = 0; i < 12; i++)
								insertList(key, (int)k[i]-48);
							
							/** STEP 4-5 **/
							for (i = 0; i < 4; i++)
							{
								for (j = 0; j < 16; j++)
									insertList(subkey, (int)k[key2[i][j]-1]-48);
								for (j = 0; j < 8; j++)
								{
									editList(temp, j, (getListElem(inputL, j)+roundFunc(inputR, subkey, j, S_P/64*1000 + (S_P%64)/16*100 + ((S_P%64)%16)/4*10 + (((S_P%64)%16)%4)/1, P_i, P_j))%2);
									editList(temp2, j, getListElem(inputR, j));
								}
								for (j = 0; j < 8; j++)
								{
									editList(inputR, j, getListElem(temp, j));
									editList(inputL, j, getListElem(temp2, j));
								}
								deleteList(subkey);
								initList(subkey);
							}
							/** STEP 4-5 **/
							
							/** STEP 6-7 **/
							for (i = 0; i < 16; i++)
							{
								if (inv_perm[i] <= 8)
									insertList(output, getListElem(inputL, inv_perm[i]-1));
								else
									insertList(output, getListElem(inputR, (inv_perm[i]-1)%8));
							}
							swap = getListElem(output, getPermInd(IP_i, perm));
							editList(output, getPermInd(IP_i, perm), getListElem(output, getPermInd(IP_j, perm)));
							editList(output, getPermInd(IP_j, perm), swap);
							if (matchResult(output, cipher))
							{
								printf("Student No: %s\n", SN);
								printf("Config: [%i, %i, %i, %i, %i]\n", IP_i, IP_j, P_i, P_j, S_P);
								printf("Ciphertext: "); printList(output);
								printf("CorrectOut: %s\n\n", cipher);
								flag = 1;
							}
							/** STEP 6-7 **/
							
							deleteList(inputL);
							deleteList(inputR);
							deleteList(temp);
							deleteList(temp2);
							deleteList(key);
							deleteList(output);
							if (flag == 1)
								break;
						}
						if (flag == 1)
							break;
					}
					if (flag == 1)
						break;
				}
				if (flag == 1)
					break;
			}
			if (flag == 1)
				break;
		}
	}
	
	free(inputL);
	free(inputR);
	free(temp);
	free(temp2);
	free(key);
	free(subkey);
	free(output);
	
	fflush(Fi);
	fclose(Fi);
	return 0;
}

int matchResult(struct List *list, char out[18])
{
	struct Node *n = list->front;
	int i = 0, x = 1;
	while (n != NULL)
	{
		if (n->bit != (int)out[i]-48)
		{
			x = 0;
			break;
		}
		n = n->next;
		i++;
	}
	return x;
}

int getPermInd(int n, int arr[16])
{
	int i = 0;
	while (i < 16)
	{
		if (arr[i]-1 == n)
			break;
		i++;
	}
	return i;
}

int roundFunc(struct List *R, struct List *K, int ind, int S_Perm, int Pi, int Pj)
{
	int i, j, retval, pow = 1000, swap;
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
	swap = perm[Pi];
	perm[Pi] = perm[Pj];
	perm[Pj] = swap;
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
			insertList(exp, getListElem(R, (i*2+j+7)%8));
			editList(exp, j, (getListElem(exp, j)+getListElem(K, i*4+j))%2);
		}
		// STEP 5a-b
		
		// STEP 5c-e
		c = S_Box[S_Perm/pow][(getListElem(exp, 0))*2 + (getListElem(exp, 3))][(getListElem(exp, 1))*2 + (getListElem(exp, 2))][1];
		insertList(temp, (int)c-48);
		c = S_Box[S_Perm/pow][(getListElem(exp, 0))*2 + (getListElem(exp, 3))][(getListElem(exp, 1))*2 + (getListElem(exp, 2))][2];
		insertList(temp, (int)c-48);
		S_Perm = S_Perm%pow;
		pow = pow/10;
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