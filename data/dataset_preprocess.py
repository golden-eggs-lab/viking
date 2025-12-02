import pandas as pd
from matplotlib import pyplot as plt
import numpy as np

def save_preprocess(dataset, write_file):
	write_name = './processed/' + write_file
	dataset.to_csv(write_name, index=False)

def pos_ints(dataset):
	mins = dataset.min()
	# print(mins)
	for col in dataset.columns:
		if mins[col] < 0:
			dataset[col] -= (mins[col] - 1)
		if mins[col] < 1:
			dataset[col] += 1
	return dataset

def one_hot_encode(df, categorical_cols=None):
	if categorical_cols == None:
		return df
	else:
		df_hot = pd.get_dummies(df, columns=categorical_cols)
		df_hot.replace([np.inf, -np.inf], np.nan, inplace=True)
		df_hot.dropna(how='any', inplace=True)
		for column in df_hot.columns:
			for categorical in categorical_cols:
				if column in categorical:
					df_hot[categorical].astype(int)
		return df_hot

def normalize(df, norm_type):
	# Remove rows containing inf or nan
	df.replace([np.inf, -np.inf], np.nan, inplace=True)
	df.dropna(how='any', inplace=True)
	print(df.head())
	means 	= df.mean()
	print(f'Means = \n{means}')
	stds 	= df.std()
	print(f'STDs = \n{stds}')
	if norm_type == 'l1':
		norm 	= (df - means) / stds
	elif norm_type == 'l2':
		norm 	= ((df - means) ** 2) / stds
	print(f'Norm means = \n{norm.mean()}')
	print(f'Norm STDs = \n{norm.std()}')
	scale_factor = 1e5 / np.max(norm.abs())
	out_df = norm.abs() * scale_factor + 1
	pos_out_df = pos_ints(out_df.astype(int))
	print(f'Output means = \n{pos_out_df.mean()}')
	print(f'Output STDs = \n{pos_out_df.std()}')

	return pos_out_df








file_path 		= './original/raisin.csv'
df 				= pd.read_csv(file_path)
processed_df 	= one_hot_encode(df, ['Class'])
pdf_l1 			= normalize(processed_df, 'l1')
save_preprocess(pdf_l1, 'l1_raisin.csv')
pdf_l2 			= normalize(processed_df, 'l2')
save_preprocess(pdf_l2, 'l2_raisin.csv')

file_path 		= './original/housing.csv'
housing_df 		= pd.read_csv(file_path)
processed_df 	= one_hot_encode(housing_df, ['ocean_proximity'])
pdf_l1 			= normalize(processed_df, 'l1')
save_preprocess(pdf_l1, 'l1_housing.csv')
pdf_l2 			= normalize(processed_df, 'l2')
save_preprocess(pdf_l2, 'l2_housing.csv')

file_path 		= './original/drybean.csv'
df 				= pd.read_csv(file_path)
processed_df 	= one_hot_encode(df, ['Class'])
pdf_l1 			= normalize(processed_df, 'l1')
save_preprocess(pdf_l1, 'l1_drybean.csv')
pdf_l2 			= normalize(processed_df, 'l2')
save_preprocess(pdf_l2, 'l2_drybean.csv')

file_path 		= './original/winequality.csv'
df 				= pd.read_csv(file_path)
processed_df 	= one_hot_encode(df, ['quality'])
pdf_l1 			= normalize(processed_df, 'l1')
save_preprocess(pdf_l1, 'l1_winequality.csv')
pdf_l2 			= normalize(processed_df, 'l2')
save_preprocess(pdf_l2, 'l2_winequality.csv')





file_path 		= './original/shuttle.csv'
shuttle_cols 	= ['Time', 'Att01', 'Att02', 'Att03', 'Att04','Att05','Att06', 'Att07', 'Att08', 'Class']
df 				= pd.read_csv(file_path, delimiter=' ', names=shuttle_cols, skiprows=1)
print('Original read-in dataset')
print(df.head())
processed_df 	= one_hot_encode(df, ['Class'])
print('One-hot encoded dataset')
print(processed_df.head())

# Calculate and output L1 norm
pdf_l1 			= normalize(processed_df, 'l1')
print('L1 normalized dataset')
print(pdf_l1.head())
save_preprocess(pdf_l1, 'l1_shuttle.csv')

# Calculate and output L2 norm
pdf_l2 			= normalize(processed_df, 'l2')
print('L2 normalized dataset')
print(pdf_l2.head())
save_preprocess(pdf_l2, 'l2_shuttle.csv')














## First pass
# col_names_exclude 	= ['Class']
# col_names_map 		= ['ocean_proximity']
# ocean_map 			= ['ISLAND', 'NEAR BAY', 'NEAR OCEAN', '<1H OCEAN', 'INLAND']	 # Input numbers in ascending order
# ocean_map.reverse()

# def print_shape(dataset, name):
# 	df_shape = dataset.shape
# 	print('Shape of ' + name + ' = ' + str(df_shape))

# 	return df_shape

# def map_categorical(dataset, map_apply, column_name):

# 	def check_vals(val, cat_opts):
# 		count = 0
# 		for cat in cat_opts:
# 			if val == cat:
# 				return count + 1
# 			count += 1

# 	dataset[column_name] 	= dataset[column_name].map(lambda x: check_vals(x, map_apply))
# 	return dataset

# def calc_max(dataset):
# 	return dataset.sum(axis=1).astype(int).max()

# def l2_norm(df):
# 	df 		= df.fillna(0)
# 	means 	= df.mean()
# 	print(f'Means = {means}')
# 	stds 	= df.std()
# 	print(f'STDs = {stds}')
# 	norm 	= ((df - means) ** 2) / stds
# 	scale_factor = 1#1e5 / np.max(norm.abs())
# 	out_df = norm * scale_factor + 1
# 	return pos_ints(out_df.astype(int))

# # Raisin
# file_name 		= 'raisin.csv'
# df_raisin 		= pd.read_csv('raisin.csv')
# df_raisin.pop('Class')
# df_raisin = pos_ints(df_raisin)
# save_preprocess(df_raisin, file_name)

# # California Housing Prices
# file_name = 'housing.csv'
# df_housing = pd.read_csv('housing.csv')
# df_housing = map_categorical(df_housing, ocean_map, col_names_map)
# df_housing = pos_ints(df_housing)
# save_preprocess(df_housing, file_name)

# # Dry Bean
# file_name = 'drybean.csv'
# df_drybean = pd.read_csv('drybean.csv')
# df_drybean.pop('Class')
# df_drybean = pos_ints(df_drybean)
# save_preprocess(df_drybean, file_name)

# # Wine Quality
# file_name = 'winequality.csv'
# df_wine = pd.read_csv('winequality.csv')
# df_wine.pop('Unnamed: 0')
# df_wine = pos_ints(df_wine)
# save_preprocess(df_wine, file_name)

# # Statlog (shuttle)
# file_name = 'shuttle.csv'
# shuttle_colnames = ['Time', 'Attribute1', 'Attribute2', 'Attribute3', 'Attribute4', 'Attribute5', 'Attribute6', 'Attribute7', 'Attribute8', 'Class']
# df_shuttle = pd.read_csv('shuttle.trn', delimiter=' ', names=shuttle_colnames)
# df_shuttle.pop('Class')
# df_shuttle = pos_ints(df_shuttle)
# save_preprocess(df_shuttle, file_name)



