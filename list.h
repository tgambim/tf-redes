

typedef int (*compare_function)(void*, void*);

struct node_s{
    void *element;
    struct node_s * next_node;
};
typedef struct node_s node;

struct list_s{
    node * head;
    node * tail;
    int size;
};

typedef struct list_s list;

void* removeElement(compare_function compare, void* element, list * list);
void* findElement(compare_function compare, void* element, list * list);
void pushElement(void* element, list * list);