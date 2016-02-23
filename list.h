/* 
 * list.h - a faxsimile of the Linux kernel's list structures,
 * macros and functions
 */


struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

/* This macro is passed the list_head member of a structure,
 * thus the next & prev point to the list_head itself */
#define LIST_HEAD_INIT(name) { &(name), &(name) }

/* This macro is passed a strucutre name, and it creates the strucure
 * and points the next and prev members of the list_head struct to the
 * list_head member. */
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list) {
    list->next = list;
    list->prev = list;
}

/* 
 * This macro points to the structure that contains the list
 * How does it work?
 * 1) (type *)0)->member casts memory address 0 to the container (struct), then gets the address of the
 * member within the struct. As we're dealing with address 0, this returns how far into the container the member.
 * 2) This address is then taken away from the actual address of the member within the container.
 * 3) Thus you get a pointer to the container the member is in.
 */

#define list_entry(ptr, type, member) (type *)((char *)(ptr) - (char *) &((type *)0)->member)

/*
 * list_first_entry - Pointer to the first entry. 
 * 'ptr' the list head.
 * 'type' is the type of struct it is embedded in
 * 'member' is the name of the list_head within the struct
 */
#define list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)

/*
 * list_last_entry - Pointer to the last entry, assumes its received the list head as the 'ptr'
 */
#define list_last_entry(ptr, type, member) list_entry((ptr)->prev, type, member)

/*
 * list_for_each - iterate over a list
 */
#define list_for_each(iterate, head) \
    for (iterate = (head)->next; iterate != (head); iterate = iterate-next)

/* 
 * list_for_each_reverse - reverse iterate over a list
 */
#define list_for_each_reverse(iterate, head) \
    for (iterate = (head)->prev; iterate != head; iterate = iterate->prev)



/*
 * This function adds 'entry' between 'prev' and 'next'
 */
static inline void __list_add(struct list_head *entry, struct list_head *prev, struct list_head *next) {
    next->prev = entry;
    entry->next = next;
    entry->prev = prev;
    prev->next = entry;
}

/* 
 * list_add inserts a new element after the list head 
 * For example:
 * list_add(&newfoo->entry, &something->list_of_foo);
 * So: 
 * 'head -> some_element -> ...' becomes
 * 'head -> new_element -> some_element -> ... '
 * */
static inline void list_add(struct list_head *entry, struct list_head *head) {
    __list_add(entry, head, head->next);
}

/*
 * Adds a new entry before the head.
 */
static inline void list_add_tail(struct list_head *entry, struct list_head *head) {
    __list_add(entry, head->prev, head);
}

/*
 * __list_del - removes the entry between prev and next
 */
static inline void __list_del(struct list_head *prev, struct list_head *next) {
    next->prev = prev;
    prev->next = next;
}


/*
 * list_del - deletes an entry from the list
 * 'entry' is the element to delete from the list
 */
static inline void list_del(struct list_head *entry) {
    __list_del(entry->prev, entry->next);
}

/*
 * Test whether a list is empty or not
 */
static inline int list_empty(const struct list_head *head) {
    return head->next == head;
}






