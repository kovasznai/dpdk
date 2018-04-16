#!/usr/bin/env stap

function open_dump(entry_p){
        printf("\n================ENTRY=======================================================\n")
	printf("%s\n", entry_p)
	dump_proc_info()
}

function dump_backtrace(entry_p)
{
        printf("----------------USER------------------\n")
        print_ubacktrace()
        printf("\n---------------KERNEL-----------------\n")
        print_backtrace()
	printf("%s\n", entry_p)
}

function close_dump(entry_p){
        printf("================EXIT========================================================\n\n")
}

function dump_proc_info(){
	printf("%d:%s(%d)[%s(%d)]\n", gettimeofday_ms(), execname(), tid(), pexecname(), ppid())
}

function dump_page_info(pointer){
	try {
		_count = @cast(pointer, "struct page", "kernel<linux/mm_types.h>")->_count->counter;
		flags = @cast(pointer, "struct page", "kernel<linux/mm_types.h>")->flags;
		mapping = @cast(pointer, "struct page", "kernel<linux/mm_types.h>")->mapping;
		_mapcount = @cast(pointer, "struct page", "kernel<linux/mm_types.h>")->_mapcount->counter;
		printf("page %p _count %d flags %x mapping %p _mapcount %d\n", pointer, _count, flags, mapping, _mapcount);
	} catch (msg) {
		printf("(ERROR page) %p %d: %s\n", pointer, pointer, msg);
	}
}

probe kernel.function("free_huge_page").call {
	page_pointer = $page;

	printf("WARNING0: IF TRACE AFTER NEXT IS enqueue_huge_page (ERROR page) then this is a duplicate trace but with page pointer %p\n", $page);
	open_dump("free_huge_page");
	dump_page_info(page_pointer);
	dump_backtrace("free_huge_page");
	close_dump("free_huge_page");
}

probe kernel.function("enqueue_huge_page").inline {
	#page_pointer = $page;
	page_pointer = pointer_arg(2);

	open_dump("enqueue_huge_page");
	dump_page_info(page_pointer);
	dump_backtrace("enqueue_huge_page");
	close_dump("enqueue_huge_page");
}

probe kernel.function("dequeue_huge_page_node").return {
	page_pointer = $return;

	open_dump("dequeue_huge_page_node");
	dump_page_info(page_pointer);
	dump_backtrace("dequeue_huge_page_node");
	close_dump("dequeue_huge_page_node");
}
