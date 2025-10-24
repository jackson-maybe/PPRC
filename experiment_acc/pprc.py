# import random
# import pandas as pd
# import time

# # Import the custom classes from their respective files
# from bloom_filter import BloomFilter
# from linear_counting import LinearCounting
# from data_provider import Data_provider

# def unique_2d_list(locations: list) -> list:
#     """
#     Removes duplicate pairs from a 2D list representing coordinates.
#     This is used to get the true count of unique locations for accuracy comparison.

#     Args:
#         locations (list): A list containing two sub-lists [ [x1, x2, ...], [y1, y2, ...] ].

#     Returns:
#         list: A list of unique (x, y) coordinate tuples.
#     """
#     # Combine the two lists into a list of coordinate pairs (tuples)
#     coordinate_pairs = list(zip(locations[0], locations[1]))
#     # Use dict.fromkeys to efficiently remove duplicates while preserving order, then convert back to a list
#     unique_coordinate_pairs = list(dict.fromkeys(coordinate_pairs))
#     return unique_coordinate_pairs

# def pprc_test(b_error_rate, l_length, length, num_provider, count_value, dataset_df, range_df, fraction):
#     """
#     Runs a single trial of the Privacy-Preserving Range Counting (PPRC) simulation.

#     Args:
#         b_error_rate (float): False positive rate for the Bloom Filters.
#         l_length (int): Bit array size for the Linear Counting sketches.
#         length (int): The side length of the square query range.
#         num_provider (int): The number of data providers to simulate.
#         count_value (int): The target density for selecting a query range.
#         dataset_df (pd.DataFrame): The main dataset.
#         range_df (pd.DataFrame): A pre-calculated dataframe with range counts.
#         fraction (float): The fraction of data each provider holds.

#     Returns:
#         tuple: A tuple containing two lists (range_count_errors, true_values) for this trial run.
#     """
#     # Filter the pre-calculated ranges to find one with the target density
#     filtered_df = range_df[range_df['RangeCount'] == count_value]
    
#     range_count_error = []
#     true_value_list = []

#     # Run the test 10 times for statistical stability
#     for _ in range(10):
#         try:
#             # Randomly select a starting point for the query range from the filtered set
#             random_row = filtered_df.sample(n=1)
#         except ValueError:
#             print(f"No data available for Count Value {count_value}. Skipping trial.")
#             continue # Skip this trial if no suitable range is found
        
#         # Define the query range based on the starting point and length
#         start_1 = random_row['Column1'].iloc[0]
#         start_2 = random_row['Column2'].iloc[0]
#         range_list_1 = [n for n in range(start_1, start_1 + length)]
#         range_list_2 = [n for n in range(start_2, start_2 + length)]
        
#         # Convert range values to strings for insertion into Bloom Filters
#         range_list_insert_1 = [str(x) for x in range_list_1]
#         range_list_insert_2 = [str(y) for y in range_list_2]
        
#         # --- Querier side: Create Query Bloom Filters ---
#         seed = random.randint(0, 10000)
#         bloom_lon_q = BloomFilter(seed=seed, capacity=length, error_rate=b_error_rate)
#         bloom_lat_q = BloomFilter(seed=seed + 1000, capacity=length, error_rate=b_error_rate)
#         bloom_lon_q.add(range_list_insert_1)
#         bloom_lat_q.add(range_list_insert_2)

#         # --- Data Provider side: Simulate multiple providers ---
#         LC_list = []
#         all_true_datasets = []

#         for provider_id in range(num_provider):
#             # Each provider has a unique seed for their data sampling
#             provider_seed = seed + provider_id
#             data = Data_provider(num_provider=provider_id, seed=provider_seed, range_list_1=range_list_1, range_list_2=range_list_2)
#             elements_true, elements_false = data.load_true_false_dataset(dataset_df, fraction=fraction)
#             all_true_datasets.append(elements_true)
            
#             lc = LinearCounting(bit_array_size=l_length, seed=seed)

#             # Check which items from the provider's data match the query BFs
#             items_to_add_to_lc = []
            
#             # Process items that are truly in range
#             for i in range(len(elements_true[0])):
#                 lon, lat = elements_true[1][i], elements_true[2][i]
#                 if bloom_lon_q.contains(lon) and bloom_lat_q.contains(lat):
#                     items_to_add_to_lc.append(f"{elements_true[0][i]},{lon},{lat}")

#             # Process items that are out of range (to simulate false positives)
#             for i in range(len(elements_false[0])):
#                 lon, lat = elements_false[1][i], elements_false[2][i]
#                 if bloom_lon_q.contains(lon) and bloom_lat_q.contains(lat):
#                     items_to_add_to_lc.append(f"{elements_false[0][i]},{lon},{lat}")

#             # Add the identified (potentially in-range) items to the LC sketch
#             lc.add(items_to_add_to_lc)
#             LC_list.append(lc)
            
#         # --- Aggregator side: Aggregate sketches and estimate ---
#         if not LC_list:
#             continue # If no providers were processed, skip aggregation

#         Agg_lc = LinearCounting(bit_array_size=l_length, seed=seed)
#         # Aggregate all LC sketches using a bitwise OR operation
#         for lc_sketch in LC_list:
#             for j in range(Agg_lc.m):
#                 # An OR operation: if either bit is 1, the result is 1
#                 Agg_lc.bit_array[j] = Agg_lc.bit_array[j] or lc_sketch.bit_array[j]
        
#         estimated_count = Agg_lc.estimate_count()

#         # --- Ground Truth Calculation ---
#         # Aggregate all 'true' datasets from all providers
#         elements_true_agg = [[], [], []]
#         for true_data in all_true_datasets:
#             elements_true_agg[0].extend(true_data[0])
#             elements_true_agg[1].extend(true_data[1])
#             elements_true_agg[2].extend(true_data[2])
        
#         # Calculate the actual number of unique items
#         true_value = len(unique_2d_list(elements_true_agg))
        
#         range_count_error.append(abs(true_value - estimated_count))
#         true_value_list.append(true_value)
    
#     return range_count_error, true_value_list


# if __name__ == "__main__":
#     # --- Configuration Parameters ---
#     # Fraction of the total dataset held by each provider
#     FRACTION_PER_PROVIDER = 0.1
#     # Paths to the datasets
#     DATASET_FILENAME = 'quantize_gowalla_data'
#     if DATASET_FILENAME == 'quantize_yelp_data':
#         DATASET_PATH = f'../dataset/spatial/{DATASET_FILENAME}.xlsx'
#         RANGE_COUNT_PATH = f'../dataset/spatial/quantize_yelp_count.csv'
#     elif DATASET_FILENAME == 'quantize_brightkite_data':
#         DATASET_PATH = f'../dataset/brightkite/{DATASET_FILENAME}.csv'
#         RANGE_COUNT_PATH = f'../dataset/brightkite/quantize_brightkite_count.csv'
#     elif DATASET_FILENAME == 'quantize_gowalla_data':
#         DATASET_PATH = f'../dataset/gowalla/{DATASET_FILENAME}.csv'
#         RANGE_COUNT_PATH = f'../dataset/gowalla/quantize_gowalla_count.csv'
#     elif DATASET_FILENAME == 'quantize_synthetic_data':
#         DATASET_PATH = f'../dataset/spatial/{DATASET_FILENAME}.csv'
#         RANGE_COUNT_PATH = f'../dataset/spatial/{DATASET_FILENAME}_count.csv'
#     else:
#         raise ValueError("Invalid DATASET_FILENAME specified.")
#     # Bloom Filter false positive rate
#     BF_ERROR_RATE = 0.0001
#     # Linear Counting sketch size (bit array length)
#     LC_LENGTH = 1024 * 8
#     # Side length of the square query range (in grid units)
#     QUERY_RANGE_LENGTH = 100
#     # Number of simulated data providers
#     NUM_PROVIDERS = 4
    
#     # --- Load Data ---
#     print("Loading datasets...")
#     try:
#         if DATASET_FILENAME == 'quantize_yelp_data':
#             main_dataset_df = pd.read_excel(DATASET_PATH)
#             range_counts_df = pd.read_csv(RANGE_COUNT_PATH)
#         else:
#             main_dataset_df = pd.read_csv(DATASET_PATH)
#             range_counts_df = pd.read_csv(RANGE_COUNT_PATH)
#     except FileNotFoundError as e:
#         print(f"Error loading files: {e}")
#         print("Please ensure the dataset files are in the correct directory.")
#         exit()
#     print("Datasets loaded successfully.")

#     # --- Experiment Execution ---
#     all_errors = []
#     all_real_counts = []
#     # Test for ranges with different data densities
#     count_value_list = [i * 10 for i in range(1, 31)]
    
#     print(f"\nStarting simulation with {NUM_PROVIDERS} providers...")
#     start_time = time.time()
    
#     for count in count_value_list:
#         print(f"Testing for range count value: {count}")
#         errors, reals = pprc_test(
#             b_error_rate=BF_ERROR_RATE,
#             l_length=LC_LENGTH,
#             length=QUERY_RANGE_LENGTH,
#             num_provider=NUM_PROVIDERS,
#             count_value=count,
#             dataset_df=main_dataset_df,
#             range_df=range_counts_df,
#             fraction=FRACTION_PER_PROVIDER
#         )
#         all_errors.extend(errors)
#         all_real_counts.extend(reals)
        
#     end_time = time.time()
    
#     # --- Results Analysis ---
#     print("\n--- Simulation Finished ---")
#     print(f"Total execution time: {end_time - start_time:.2f} seconds")
    
#     if not all_real_counts:
#         print("No results were generated. The simulation may have encountered issues.")
#     else:
#         # Calculate Mean Absolute Error (MAE) and Mean Relative Error (MRE)
#         total_absolute_error = sum(all_errors)
#         total_relative_error = 0
#         valid_relative_errors = 0
        
#         for i in range(len(all_real_counts)):
#             if all_real_counts[i] > 0:
#                 total_relative_error += all_errors[i] / all_real_counts[i]
#                 valid_relative_errors += 1
        
#         mae = total_absolute_error / len(all_real_counts)
#         mre = total_relative_error / valid_relative_errors if valid_relative_errors > 0 else 0
        
#         print("\n--- Results ---")
#         # print("Real range counts list: ", all_real_counts)
#         # print("Range count errors list: ", all_errors)
#         print(f"Mean Absolute Error (MAE): {mae:.4f}")
#         print(f"Mean Relative Error (MRE): {mre:.4%}")







import random
import pandas as pd
import time

# Import the custom classes from their respective files
from bloom_filter import BloomFilter
from linear_counting import LinearCounting
from data_provider import Data_provider

def unique_2d_list(locations: list) -> list:
    """
    Removes duplicate pairs from a 2D list representing coordinates.
    This is used to get the true count of unique locations for accuracy comparison.

    Args:
        locations (list): A list containing two sub-lists [ [x1, x2, ...], [y1, y2, ...] ].

    Returns:
        list: A list of unique (x, y) coordinate tuples.
    """
    # Combine the two lists into a list of coordinate pairs (tuples)
    coordinate_pairs = list(zip(locations[0], locations[1]))
    # Use dict.fromkeys to efficiently remove duplicates while preserving order, then convert back to a list
    unique_coordinate_pairs = list(dict.fromkeys(coordinate_pairs))
    return unique_coordinate_pairs

def pprc_test(b_error_rate, l_length, length, num_provider, dataset_df, fraction):
    
    """
    Runs a single trial of the Privacy-Preserving Range Counting (PPRC) simulation
    with a randomly generated query range.

    Args:
        b_error_rate (float): False positive rate for the Bloom Filters.
        l_length (int): Bit array size for the Linear Counting sketches.
        length (int): The side length of the square query range.
        num_provider (int): The number of data providers to simulate.
        dataset_df (pd.DataFrame): The main dataset.
        fraction (float): The fraction of data each provider holds.

    Returns:
        tuple: A tuple containing the absolute error and the true value for this trial.
    """
    # --- MODIFICATION START: Randomly generate query range ---
    # Get the boundaries of the entire dataset
    min_col1, max_col1 = dataset_df['Column1'].min(), dataset_df['Column1'].max()
    min_col2, max_col2 = dataset_df['Column2'].min(), dataset_df['Column2'].max()

    # Randomly select a starting point ensuring the 100x100 range fits within the boundaries
    try:
        start_1 = random.randint(min_col1, max_col1 - length)
        start_2 = random.randint(min_col2, max_col2 - length)
    except ValueError:
        print(f"Dataset range is too small to fit a {length}x{length} query. Skipping trial.")
        return None, None # Return None if range cannot be generated
        
    # Define the query range
    range_list_1 = [n for n in range(start_1, start_1 + length)]
    range_list_2 = [n for n in range(start_2, start_2 + length)]
    # --- MODIFICATION END ---

    # Convert range values to strings for insertion into Bloom Filters
    range_list_insert_1 = [str(x) for x in range_list_1]
    range_list_insert_2 = [str(y) for y in range_list_2]
    
    
    

    
    
    # --- Querier side: Create Query Bloom Filters ---
    seed = random.randint(0, 10000)
    bloom_lon_q = BloomFilter(seed=seed, capacity=length, error_rate=b_error_rate)
    bloom_lat_q = BloomFilter(seed=seed + 1000, capacity=length, error_rate=b_error_rate)
    bloom_lon_q.add(range_list_insert_1)
    bloom_lat_q.add(range_list_insert_2)

    # --- Data Provider side: Simulate multiple providers ---
    LC_list = []
    all_true_datasets = []

    for provider_id in range(num_provider):
        # Each provider has a unique seed for their data sampling
        provider_seed = seed + provider_id
        data = Data_provider(num_provider=provider_id, seed=provider_seed, range_list_1=range_list_1, range_list_2=range_list_2)
        elements_true, elements_false = data.load_true_false_dataset(dataset_df, fraction=fraction)
        all_true_datasets.append(elements_true)
        
        lc = LinearCounting(bit_array_size=l_length, seed=seed)

        # Check which items from the provider's data match the query BFs
        items_to_add_to_lc = []
        
        # Process items that are truly in range
        for i in range(len(elements_true[0])):
            lon, lat = elements_true[1][i], elements_true[2][i]
            if bloom_lon_q.contains(lon) and bloom_lat_q.contains(lat):
                items_to_add_to_lc.append(f"{elements_true[0][i]},{lon},{lat}")

        # Process items that are out of range (to simulate false positives)
        for i in range(len(elements_false[0])):
            lon, lat = elements_false[1][i], elements_false[2][i]
            if bloom_lon_q.contains(lon) and bloom_lat_q.contains(lat):
                items_to_add_to_lc.append(f"{elements_false[0][i]},{lon},{lat}")

        # Add the identified (potentially in-range) items to the LC sketch
        lc.add(items_to_add_to_lc)
        LC_list.append(lc)
    
        
    # --- Aggregator side: Aggregate sketches and estimate ---
    if not LC_list:
         raise ValueError("LC_list is empty. This indicates that no data providers were processed successfully in the loop.")

    Agg_lc = LinearCounting(bit_array_size=l_length, seed=seed)
    # Aggregate all LC sketches using a bitwise OR operation
    for lc_sketch in LC_list:
        for j in range(Agg_lc.m):
            # An OR operation: if either bit is 1, the result is 1
            Agg_lc.bit_array[j] = Agg_lc.bit_array[j] or lc_sketch.bit_array[j]
    
    estimated_count = Agg_lc.estimate_count()

    # --- Ground Truth Calculation ---
    # Aggregate all 'true' datasets from all providers
    elements_true_agg = [[], [], []]
    for true_data in all_true_datasets:
        elements_true_agg[0].extend(true_data[0])
        elements_true_agg[1].extend(true_data[1])
        elements_true_agg[2].extend(true_data[2])
    
    # Calculate the actual number of unique items
    true_value = len(unique_2d_list(elements_true_agg))
    
    range_count_error = abs(true_value - estimated_count)
    
    return range_count_error, true_value


if __name__ == "__main__":
    # --- Configuration Parameters ---
    # Fraction of the total dataset held by each provider
    FRACTION_PER_PROVIDER = 0.1
    # Paths to the datasets
    DATASET_FILENAME = 'synthetic_data_100000'
    if DATASET_FILENAME == 'quantize_yelp_data':
        DATASET_PATH = f'../datasets/spatial/{DATASET_FILENAME}.xlsx'
    elif DATASET_FILENAME == 'quantize_brightkite_data':
        DATASET_PATH = f'../datasets/brightkite/{DATASET_FILENAME}.csv'
    elif DATASET_FILENAME == 'quantize_gowalla_data':
        DATASET_PATH = f'../datasets/gowalla/{DATASET_FILENAME}.csv'
    elif DATASET_FILENAME == 'synthetic_data_100000':
        DATASET_PATH = f'../datasets/synthetic_datasets/{DATASET_FILENAME}.csv'
    else:
        raise ValueError("Invalid DATASET_FILENAME specified.")
    # Bloom Filter false positive rate
    BF_ERROR_RATE = 0.0001
    # Linear Counting sketch size (bit array length)
    LC_LENGTH = 1024 * 8
    # Side length of the square query range (in grid units)
    QUERY_RANGE_LENGTH = 100
    # Number of simulated data providers
    NUM_PROVIDERS = 10
    
    # --- Load Data ---
    print("Loading datasets...")
    try:
        if DATASET_FILENAME == 'quantize_yelp_data':
            main_dataset_df = pd.read_excel(DATASET_PATH)
        else:
            main_dataset_df = pd.read_csv(DATASET_PATH)
    except FileNotFoundError as e:
        print(f"Error loading files: {e}")
        print("Please ensure the dataset files are in the correct directory.")
        exit()
    print("Datasets loaded successfully.")

    # --- Experiment Execution ---
    all_errors = []
    all_real_counts = []

    
    print(f"\nStarting simulation with {NUM_PROVIDERS} providers...")
    start_time = time.time()
    
    for number_trial_iter in range(100):
        errors, reals = pprc_test(
            b_error_rate=BF_ERROR_RATE,
            l_length=LC_LENGTH,
            length=QUERY_RANGE_LENGTH,
            num_provider=NUM_PROVIDERS,
            dataset_df=main_dataset_df,
            fraction=FRACTION_PER_PROVIDER
        )
        all_errors.append(errors)
        all_real_counts.append(reals)
        
    end_time = time.time()
    
    # --- Results Analysis ---
    print("\n--- Simulation Finished ---")
    print(f"Total execution time: {end_time - start_time:.2f} seconds")
    
    if not all_real_counts:
        print("No results were generated. The simulation may have encountered issues.")
    else:
        # Calculate Mean Absolute Error (MAE) and Mean Relative Error (MRE)
        total_absolute_error = sum(all_errors)
        total_relative_error = 0
        valid_relative_errors = 0
        
        for i in range(len(all_real_counts)):
            if all_real_counts[i] > 0:
                total_relative_error += all_errors[i] / all_real_counts[i]
                valid_relative_errors += 1
        
        mae = total_absolute_error / len(all_real_counts)
        mre = total_relative_error / valid_relative_errors if valid_relative_errors > 0 else 0
        
        print("\n--- Results ---")
        # print("Real range counts list: ", all_real_counts)
        # print("Range count errors list: ", all_errors)
        print(f"Mean Absolute Error (MAE): {mae:.4f}")
        print(f"Mean Relative Error (MRE): {mre:.4%}")


