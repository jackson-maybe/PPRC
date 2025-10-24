import math
import mmh3

class LinearCounting:
    """
    Implements the Linear Counting algorithm for cardinality estimation.
    
    Linear Counting is a simple and effective algorithm for estimating the number of
    distinct elements (cardinality) in a large set.
    """
    def __init__(self, bit_array_size: int, seed: int):
        """
        Initializes the Linear Counting sketch.

        Args:
            bit_array_size (int): The size of the bit array (m).
            seed (int): A seed for the hash function.
        """
        self.m = bit_array_size
        self.bit_array = [0] * self.m
        self.seed = seed

    def add(self, items: list):
        """
        Adds a list of items to the Linear Counting sketch.

        Args:
            items (list): A list of items to add. Each item should be hashable.
        """
        for item in items:
            index = mmh3.hash(str(item), seed=self.seed) % self.m
            self.bit_array[index] = 1

    def estimate_count(self) -> int:
        """
        Estimates the cardinality of the set of added items.

        Returns:
            int: The estimated number of distinct items.
        """
        # Count the number of zero bits in the bit array
        V = self.bit_array.count(0)
        
        if V == 0:
            # If the array is full, the estimation is unreliable.
            # Return a theoretical upper bound, though it might be an overestimation.
            return self.m
            
        # The core formula for Linear Counting estimation
        result = -self.m * math.log(V / self.m)
        return math.floor(result)