import random
import pandas as pd

class Data_provider:
    """
    Simulates a data provider that can load and partition a dataset
    based on a specified query range.
    """
    def __init__(self, num_provider: int, seed: int, range_list_1: list, range_list_2: list):
        """
        Initializes the Data Provider.

        Args:
            num_provider (int): Identifier for the provider (not used in current logic but good for extension).
            seed (int): A seed for random operations.
            range_list_1 (list): A list of values defining the query range for the first dimension.
            range_list_2 (list): A list of values defining the query range for the second dimension.
        """
        self.n = num_provider
        self.seed = seed
        self.range_min_1 = range_list_1[0]
        self.range_max_1 = range_list_1[-1]
        self.range_min_2 = range_list_2[0]
        self.range_max_2 = range_list_2[-1]
    
    def load_true_false_dataset(self, dataset_df: pd.DataFrame, fraction: float) -> tuple:
        """
        Randomly samples a fraction of the dataset and splits it into two parts:
        one with data points inside the query range ('true') and one with points
        outside the range ('false').

        Args:
            dataset_df (pd.DataFrame): The source dataframe containing the data.
            fraction (float): The fraction of the dataset to sample (e.g., 0.1 for 10%).

        Returns:
            tuple: A tuple containing two lists (elements_true, elements_false).
                   Each list contains three sub-lists: [car_ids, column1_values, column2_values].
        """
        # Sample a fraction of the dataframe without replacement
        sampled_df = dataset_df.sample(frac=fraction, replace=False, random_state=self.seed)
        
        # Filter for data points that fall within the specified 2D range
        in_range_mask = (
            (sampled_df['Column1'] >= self.range_min_1) & (sampled_df['Column1'] <= self.range_max_1) &
            (sampled_df['Column2'] >= self.range_min_2) & (sampled_df['Column2'] <= self.range_max_2)
        )
        sampled_true_df = sampled_df[in_range_mask]
        
        # The remaining data points are outside the range
        sampled_false_df = sampled_df[~in_range_mask]
        
        # Format the 'true' elements into lists of strings
        elements_true = [
            sampled_true_df['car_id'].astype(str).tolist(),
            sampled_true_df['Column1'].astype(str).tolist(),
            sampled_true_df['Column2'].astype(str).tolist()
        ]
        
        # Format the 'false' elements into lists of strings
        elements_false = [
            sampled_false_df['car_id'].astype(str).tolist(),
            sampled_false_df['Column1'].astype(str).tolist(),
            sampled_false_df['Column2'].astype(str).tolist()
        ]
        
        return elements_true, elements_false