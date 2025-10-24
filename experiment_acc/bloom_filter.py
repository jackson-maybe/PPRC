import math
import mmh3

class BloomFilter:
    """
    Implements a standard Bloom Filter data structure.
    
    A Bloom filter is a space-efficient probabilistic data structure that is used to
    test whether an element is a member of a set. False positive matches are possible,
    but false negatives are not.
    """
    def __init__(self, seed: int, capacity: int, error_rate: float):
        """
        Initializes the Bloom Filter.

        Args:
            seed (int): A seed for the hash functions to ensure reproducibility.
            capacity (int): The estimated number of items to be stored.
            error_rate (float): The desired false positive probability.
        """
        self.capacity = capacity
        self.error_rate = error_rate
        self.seed = seed
        self.size = self._get_size(capacity, error_rate)
        self.num_hashes = self._get_num_hashes(self.size, capacity)
        self.bit_array = [0] * self.size

    def _get_size(self, n: int, p: float) -> int:
        """
        Calculates the optimal size of the bit array.

        Args:
            n (int): The number of items to be stored.
            p (float): The false positive rate.

        Returns:
            int: The calculated size of the bit array.
        """
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)

    def _get_num_hashes(self, m: int, n: int) -> int:
        """
        Calculates the optimal number of hash functions.

        Args:
            m (int): The size of the bit array.
            n (int): The number of items to be stored.

        Returns:
            int: The optimal number of hash functions.
        """
        k = (m / n) * math.log(2)
        return int(k)

    def add(self, items: list):
        """
        Adds a list of items to the Bloom Filter.

        Args:
            items (list): A list of items to add. Each item should be hashable.
        """
        for item in items:
            for i in range(self.num_hashes):
                # Use a different seed for each hash function to simulate multiple hash functions
                hash_value = mmh3.hash(str(item), seed=i + self.seed) % self.size
                self.bit_array[hash_value] = 1

    def contains(self, item) -> int:
        """
        Checks if an item is possibly in the Bloom Filter.

        Args:
            item: The item to check.

        Returns:
            int: 1 if the item is possibly in the set (could be a true or false positive),
                 0 if the item is definitely not in the set.
        """
        for i in range(self.num_hashes):
            hash_value = mmh3.hash(str(item), seed=i + self.seed) % self.size
            if self.bit_array[hash_value] == 0:
                return 0  # Definitely not in the set
        return 1 # Possibly in the set