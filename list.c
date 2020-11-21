#include <stdlib.h>
#include "list.h"

list *list_init(void){
    list *l = malloc(sizeof(list));
    l->size=0;
    l->head = NULL;
    l->tail = NULL;
    return l;
}

void pushElement(void* element, list * list){
    node * nodeElement;
    nodeElement = malloc(sizeof(node));
    nodeElement->element = element;

    nodeElement->next_node=NULL;
    if(list->size>0){
        list->tail->next_node = nodeElement;
    }else{
        list->head=nodeElement;
    }
    list->tail=nodeElement;
    list->size++;
}

void* removeElement(compare_function compare, void* element, list * list){
    node * target_node;
    node * curNode = list->head;

    if(list->size!=0){
        //o primeiro nó é o desejado
        if(compare(curNode->element, element) == 1) {
            list->head = curNode->next_node;
            target_node = curNode;
        }else {
            /*
             * procura sempre deixando o curNode desajado em next curNode, assim consegue atualizar as referencias
             * curNode -> curNode anterior do desejado
             * curNode->next_node -> node desejado
             * curNode->next_node->next_node -> curNode posterior do desejado
             */
            while (curNode->next_node != NULL && compare(curNode->next_node->element, element) != 1) {
                curNode = curNode->next_node;
            }
            if (curNode->next_node != NULL) return NULL; //nao achou

            target_node = curNode->next_node;
            curNode->next_node = curNode->next_node->next_node;
        }
        list->size--;
        return target_node->element;
    }
}

void* findElement(compare_function compare, void* element, list * list){
    node * curNode = list->head;
    if(list->size!=0) {
        //o primeiro nó é o desejado
        if (compare(curNode->element, element) == 1) {
            return curNode->element;
        } else {
            /*
             * procura sempre deixando o curNode desajado em next curNode, assim consegue atualizar as referencias
             * curNode -> curNode anterior do desejado
             * curNode->next_node -> node desejado
             * curNode->next_node->next_node -> curNode posterior do desejado
             */
            while (curNode->next_node != NULL && compare(curNode->next_node->element, element) != 1) {
                curNode = curNode->next_node;
            }
            if (curNode->next_node == NULL) return NULL; //nao achou

            return curNode->next_node->element;
        }
    }else
        return NULL;
}