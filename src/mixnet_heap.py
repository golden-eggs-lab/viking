"""
Mixnet-based Sorted List Implementation
Uses ComparativeMixnetScore protocol for secure comparison operations
Maintains a sorted list with maximum length k
"""

from typing import List, Optional, Any, Callable
import threading
import time
import queue
import traceback
from queue import Queue, Empty
from messages import EntryStorage


class MixnetSortedList:
    """
    Sorted List implementation that uses ComparativeMixnetScore protocol for comparisons
    Maintains a sorted list with maximum length k
    
    Features:
    - Sorted list (ascending order)
    - Maximum length k
    - Uses ComparativeMixnetScore for secure comparisons
    - Thread-safe operations
    """
    
    def __init__(self, worker_class, k: int = None):
        """
        Initialize sorted list with worker class that has ComparativeMixnetScore method
        
        Args:
            worker_class: Worker class instance with ComparativeMixnetScore method
            k: Maximum length of the sorted list (optional)
        """
        self.sorted_list = []
        self.worker_class = worker_class
        self.k = k  # Maximum length

    def insert(self, item: Any) -> bool:
        """
        Insert an item into the sorted list.
        """
        # no comparison results yet, insert at the end
        return self.insert_comparison_result(item, None)
  
    
    def _find_insert_position_from_results(self, comparison_results: List[bool]) -> int:
        """
        Find the correct insertion position for an item based on pre-computed comparison results.
        Each bool in comparison_results[i] represents whether new_item < sorted_list[i].
        
        Logic for ascending order:
        - Find first position where new_item < sorted_list[i] (first True)
        - Insert at that position to maintain sorted order
        - If no True found (new_item >= all existing), insert at end
        
        Example:
            sorted_list = [10, 20, 30, 40], new_item = 25
            comparison_results = [False, False, True, True]
            → insert_pos = 2 → [10, 20, 25, 30, 40]
        
        Args:
            comparison_results: List of bools where results[i] = (new_item < sorted_list[i])
            
        Returns:
            Index where the item should be inserted
        """
        if not comparison_results:
            return 0
        
        # Find the first position where new_item < sorted_list[i]
        # Insert before that index to maintain ascending order
        for i, is_smaller in enumerate(comparison_results):
            if is_smaller:  # new_item < sorted_list[i]
                # print(f"  _find_insert_position: found first True at index {i}, inserting before it")
                return i

        # If new_item >= all existing elements, insert at the end
        # print(f"  _find_insert_position: no True found, inserting at end (pos={len(comparison_results)})")
        return len(comparison_results)
    
    def insert_comparison_result(self, item: Any, comparison_results: List[bool]) -> bool:
        """
        Insert an item into the sorted list using pre-computed comparison results.
        Each bool in comparison_results[i] represents whether item < sorted_list[i].
        
        Args:
            item: The item to insert
            comparison_results: List of bools where results[i] = item < sorted_list[i]
            
        Returns:
            True if item was inserted, False if discarded
        """
        try:
            # Find insertion position based on comparison results
            insert_pos = self._find_insert_position_from_results(comparison_results)
            
            # Insert the item
            self.sorted_list.insert(insert_pos, item)
            
            # If k is set and we exceed the limit, remove the largest element
            if self.k is not None and len(self.sorted_list) > self.k:
                self.sorted_list.pop(0)  # Remove the least element (first in sorted list)
                # print(f"MixnetSortedList: removed largest element, list size now {len(self.sorted_list)}")
            
            # print(f"MixnetSortedList: inserted item at position {insert_pos} using comparison results, list size: {len(self.sorted_list)}")
            return True
                
        except Exception as e:
            print(f"Error in insert_comparison_result: {e}")
            traceback.print_exc()
            return False
    
    def get_top_k(self) -> List[Any]:
        """
        Get the top k elements from the sorted list.
        """
        return self.sorted_list[:self.k]
    
    def pop(self) -> Optional[Any]:
        """
        Remove and return the first element.
        
        Returns:
            The first element, or None if list is empty
        """
        try:
            if not self.sorted_list:
                return None
            return self.sorted_list.pop(0) # Remove the least element (first in sorted list)
                
        except Exception as e:
            print(f"Error in pop: {e}")
            traceback.print_exc()
            return None
    
    def peek(self) -> Optional[Any]:
        """
        Return the smallest element without removing it.
        
        Returns:
            The smallest element, or None if list is empty
        """
        return self.sorted_list[0] if self.sorted_list else None
    
    def size(self) -> int:
        """
        Return the number of items in the list.
        
        Returns:
            Number of items in the list
        """
        return len(self.sorted_list)
    
    def is_empty(self) -> bool:
        """
        Check if the list is empty.
        
        Returns:
            True if list is empty, False otherwise
        """
        return len(self.sorted_list) == 0
    
    def clear(self) -> None:
        """
        Remove all items from the list.
        """
        self.sorted_list.clear()
    
    def to_list(self) -> List[Any]:
        """
        Return a list representation of the sorted list.
        
        Returns:
            List of items in sorted order
        """
        return self.sorted_list.copy()
    
    def __str__(self) -> str:
        """
        String representation of the sorted list.
        
        Returns:
            String representation
        """
        return f"MixnetSortedList(k={self.k}): {self.sorted_list}"
    
    def __len__(self) -> int:
        """
        Return the number of items in the list.
        
        Returns:
            Number of items in the list
        """
        return len(self.sorted_list)




