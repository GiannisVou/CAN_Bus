#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define LEN 10			// Length of id arrays.
#define SLEEP_TIME 2		//in seconds.

/*	Simulation of Can bus nodes.

	Every node have saved an array of id's
	that can select upon a counter,specified
	for each node.Nodes exchange messages in
	this way, and can verify the id of sender.			
	Reset assigns new random values to counters.
*/

pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_barrier_t bar, bar2;

int id_one[LEN] = { 22, 189, 77, 165, 542, 612, 188, 531, 379, 444 };
int id_two[LEN] = { 734, 839, 941, 1243, 1003, 694, 1257, 732, 806, 978};
int id_three[LEN] = { 2004, 1884, 1463, 1752, 2043, 1469, 1988, 2000, 1636, 1927};

char msg[8] = "Message";
int Frame_id;
char Frame_message[8];

int counter1, counter2, counter3;

// very simple encrypt/decrypt 
// functions, applied on data.

void encrypt_data(char *data)
{
	char *t;
	t = data;

	while(*t != '\0') {
		*t = (*t) + 2;
		t++;
	}	
}

void decrypt_data(char *data)
{
	char *t;
	t = data;

	while(*t != '\0') {
		*t = (*t) - 2;
		t++;
	}	
}

int decode(int p)	// finds out the node who sended the message.
{
	if( id_one[ (counter1 - 1) % LEN ] == p )
		return 1;
	if( id_two[ (counter2 - 1) % LEN ] == p )
		return 2;
	if( id_three[ (counter3 - 1) % LEN ] == p )
		return 3;
	return 0;
}

void * node_one(void *arg) 
{
	int id, sender;
	id = (int *) arg;
	char data[8];

	// node1 sends message.
	Frame_id = id_one[counter1%LEN];
	strcpy(data, "one");
	encrypt_data(data);
	strcpy(Frame_message, data);
	counter1++;
	sleep(SLEEP_TIME);	
	printf("\n>>>> <1> Written on CANBus :ID:%4d Data: %s\n\n",Frame_id, Frame_message);
	
	pthread_barrier_wait(&bar);		//1

	pthread_barrier_wait(&bar);		//3

	printf("NODE1 READS: CANBus :ID:%4d Data: %s\n",Frame_id, Frame_message);
	
	pthread_mutex_lock(&mtx);
		if( (sender = decode(Frame_id) ) ) {
			strcpy(data, Frame_message);
			decrypt_data(data);	
			printf("Valid MESSAGE FROM NODE:%d Data: %s\n",sender, data);
		}
		else
			printf("REJECTS MESSAGE(Invalid id)\n");	
	pthread_mutex_unlock(&mtx);

	pthread_barrier_wait(&bar);	//4

	// node1 sends message.
	Frame_id = id_one[counter1%LEN];
	strcpy(data, "new");
	encrypt_data(data);
	strcpy(Frame_message, data);
	counter1++;
	sleep(SLEEP_TIME);	
	printf("\n>>>> <1> Written on CANBus :ID:%4d Data: %s\n\n",Frame_id, Frame_message);
	
	pthread_barrier_wait(&bar);		//5
	

	pthread_barrier_wait(&bar);		//7
	
	printf("NODE1 READS: CANBus :ID:%4d Data: %s\n",Frame_id, Frame_message);
	
	pthread_mutex_lock(&mtx);
		if( (sender = decode(Frame_id) ) ) {
			strcpy(data, Frame_message);
			decrypt_data(data);	
			printf("Valid MESSAGE FROM NODE:%d Data: %s\n",sender, data);
		}
		else
			printf("REJECTS MESSAGE(Invalid id)\n");	
	pthread_mutex_unlock(&mtx);




	pthread_exit(NULL);	
}

void * node_two(void * arg)
{
	int id, sender;
	id = (int *) arg;
	char data[8];

	pthread_barrier_wait(&bar);		//1
	
	pthread_mutex_lock(&mtx);	
		printf("\t\t\t\t\tNODE2 READS: CANBus :ID:%4d Data: %s\n",Frame_id, Frame_message);
	
		if( (sender = decode(Frame_id)) ) {
			strcpy(data, Frame_message);
			decrypt_data(data);
			printf("\t\t\t\t\tValid MESSAGE FROM NODE:%d Data: %s\n",sender, data);
		}
		else
			printf("\t\t\t\t\tREJECTS MESSAGE(Invalid id)\n");	
	pthread_mutex_unlock(&mtx);	
	
	pthread_barrier_wait(&bar2);		//2
	
	// Node 2 sends a message on CAN Bus now.	
	Frame_id = id_two[counter2%LEN];
	strcpy(data, "two");
	encrypt_data(data);	
	strcpy(Frame_message, data);
	counter2++;	
	sleep(SLEEP_TIME);	
	printf("\n>>>> <2> Written on CANBus :ID:%4d Data: %s\n\n",Frame_id, Frame_message);
	
	pthread_barrier_wait(&bar);		//3
	pthread_barrier_wait(&bar);		//4
	pthread_barrier_wait(&bar);		//5

	pthread_mutex_lock(&mtx);	
		printf("\t\t\t\t\tNODE2 READS: CANBus :ID:%4d Data: %s\n",Frame_id, Frame_message);
	
		if( (sender = decode(Frame_id)) ) {
			strcpy(data, Frame_message);
			decrypt_data(data);	
			printf("\t\t\t\t\tValid MESSAGE FROM NODE:%d Data: %s\n",sender, data);
		}	
		else
			printf("\t\t\t\t\tREJECTS MESSAGE(Invalid id)\n");	
	pthread_mutex_unlock(&mtx);	
	
	pthread_barrier_wait(&bar2);		//6

	pthread_barrier_wait(&bar);		//7

	pthread_mutex_lock(&mtx);	
		printf("\t\t\t\t\tNODE2 READS: CANBus :ID:%4d Data: %s\n",Frame_id, Frame_message);
	
		if( (sender = decode(Frame_id)) ) {
			strcpy(data, Frame_message);
			decrypt_data(data);	
			printf("\t\t\t\t\tValid MESSAGE FROM NODE:%d Data: %s\n",sender, data);
		}	
		else
			printf("\t\t\t\t\tREJECTS MESSAGE(Invalid id)\n");	
	pthread_mutex_unlock(&mtx);	


	pthread_exit(NULL);
}

void * node_three(void * arg)
{
	int id, sender;
	char data[8];

	id = (int *) arg;

	pthread_barrier_wait(&bar); //1

	pthread_mutex_lock(&mtx);
		printf("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tNODE3 READS: CANBus :ID:%4d Data: %s\n",Frame_id, Frame_message);

		if( (sender = decode(Frame_id) )) {
			strcpy(data, Frame_message);
			decrypt_data(data);	
			printf("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tValid MESSAGE FROM NODE:%d Data: %s\n",sender, data);
		}	
		else
			printf("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tREJECTS MESSAGE(Invalid id)\n");	
	pthread_mutex_unlock(&mtx);
	
	pthread_barrier_wait(&bar2);		//2
	
	pthread_barrier_wait(&bar);		//3

	printf("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tNODE3 READS: CANBus :ID:%4d Data: %s\n",Frame_id, Frame_message);

	pthread_mutex_lock(&mtx);
		if( ( sender = decode(Frame_id) ) ) {
			strcpy(data, Frame_message);
			decrypt_data(data);	
			printf("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tValid MESSAGE FROM NODE:%d Data: %s\n",sender, data);
		}
		else
			printf("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tREJECTS MESSAGE(Invalid id)\n");	
	pthread_mutex_unlock(&mtx);
	
	pthread_barrier_wait(&bar);		//4
	pthread_barrier_wait(&bar);		//5

	pthread_mutex_lock(&mtx);
		printf("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tNODE3 READS: CANBus :ID:%4d Data: %s\n",Frame_id, Frame_message);

		if( (sender = decode(Frame_id) ) ) {
			strcpy(data, Frame_message);
			decrypt_data(data);
			printf("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tValid MESSAGE FROM NODE:%d Data: %s\n",sender, data);
		}	
		else
			printf("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tREJECTS MESSAGE(Invalid id)\n");	
	pthread_mutex_unlock(&mtx);
	
	pthread_barrier_wait(&bar2);		//6

//--------------------Invalid message -------------------
	//Now node3 will attempt to send 
	//a message with an invalid id.
	int invalid_id = id_three[counter3 + 3] % LEN;
	Frame_id = invalid_id;
	strcpy(data, "badmsg");
	encrypt_data(data);
	strcpy(Frame_message, data);
	counter3++;
	sleep(SLEEP_TIME);	
	printf("\n>>>> <3> Written on CANBus :ID:%4d Data: %s\n\n",Frame_id, Frame_message);
	
	pthread_barrier_wait(&bar);		//7	


	pthread_exit(NULL);
}

void reset_counters(void)
{
	srand(time(NULL));

	counter1 = rand() % LEN;
	counter2 = rand() % LEN;	
	counter3 = rand() % LEN;	
}

int main(int argc,char *argv[])
{
	pthread_t node[3];
	
	pthread_barrier_init(&bar,NULL,3);
	pthread_barrier_init(&bar2,NULL,2);
	
	printf("Small simulation of Messages on the bus.\n");	
	reset_counters();
	printf("Reseting counters: counter1: %d counter2: %d counter3: %d\n",counter1, counter2, counter3);

	// Creating threads to simulate nodes.

	pthread_create(&node[0], NULL, (void *)node_one , (void *)1);
	pthread_create(&node[1], NULL, (void *)node_two , (void *)2);
	pthread_create(&node[2], NULL, (void *)node_three , (void *)3);
		
	for( int i = 0; i < 3; i++)
		pthread_join(node[i],NULL);

	return 0;
}
