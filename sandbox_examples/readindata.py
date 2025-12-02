import pandas as pd

file_path = '/Users/jonald/Desktop/UMN_Masters_Schoolwork/2022Fall/DSCI 8760/FedTopK/FedTopK_Dev/housing.csv'
num_rows_per_party  = 1000
row_numbers_party01 = list(range(0,num_rows_per_party))
row_numbers_party02 = list(range(num_rows_per_party,2 * num_rows_per_party))
row_numbers_party03 = list(range(2 * num_rows_per_party,3 * num_rows_per_party))

def ReadDataHorizontal(file_location, row_numbers):
    cols = list(pd.read_csv(file_location, nrows = 1))
    start_ind       = row_numbers[0]
    row_count       = len(row_numbers)
    row_ID          = row_numbers
    data_series_tmp = pd.read_csv(file_location, skiprows = range(1,start_ind), nrows = row_count, usecols = [i for i in cols if i != 'ocean_proximity'])
    data_series_tmp = data_series_tmp.set_axis(row_ID)
    return data_series_tmp


# print(row_numbers_party01)
data_series01 = ReadDataHorizontal(file_path, row_numbers_party01)

# sum01 = pd.series()
sum01 = data_series01.sum(axis=1).sort_values(ascending=False)
print(sum01.iloc[0:5])

print(sum01.iloc[0:5].index[0])
print(sum01.iloc[0:5].values[0])


