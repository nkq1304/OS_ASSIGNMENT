#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t * q) {
	return (q->size == 0);
}

void enqueue(struct queue_t * q, struct pcb_t * proc) {
	/* TODO: put a new process to queue [q] */
	if (q->size < MAX_QUEUE_SIZE && proc != NULL) {

		q->proc[q->size] = proc;
		q->size++;
	}
}

struct pcb_t * dequeue(struct queue_t * q) {
	/* TODO: return a pcb whose prioprity is the highest
	 * in the queue [q] and remember to remove it from q
	 * */
	if (q->size > 0) {
		// Find the pcb whose priority is the highest
		int highest_p = 0;

		for (int i = 0; i < q->size; i++) {
			if (q->proc[i]->priority > q->proc[highest_p]->priority) {
				highest_p = i;
			}
		}
		// Get the pcb whose priority is the highest
		struct pcb_t * next_proc = q->proc[highest_p];

		// Delete the pcb from the queue
		for (int i = highest_p; i < q->size - 1; i++) {
			q->proc[i] = q->proc[i + 1];
		}

		q->proc[q->size - 1] = NULL;
		q->size--;

		// Return the pcb whose priority is the highest
		return next_proc;
	}
	return NULL;
}

