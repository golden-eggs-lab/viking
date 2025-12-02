import pandas as pd
import numpy as np
# from scipy import optimize

# Read-in data
df_raisin 	= pd.read_csv('raisin_preprocess.csv')
df_housing 	= pd.read_csv('housing_preprocess.csv')
df_drybean 	= pd.read_csv('drybean_preprocess.csv')
df_wine 	= pd.read_csv('winequality_preprocess.csv')
df_shuttle 	= pd.read_csv('shuttle_preprocess.csv')

# How does number of parties impact? Don't care, fix number of parties and workers (3 and 3)...
# k = 8? 16? 32?
k_test_matrix = [2, 4, 8, 16, 32, 64, 128, 256]

# Initialize query weights
qw = np.ones(df_raisin.shape[1])

# Assign columns
numParties 	= 3
raisin_cols = df_raisin.columns
num_cols 	= len(raisin_cols)
readColInds = []

for role in range(3):
	if role == 0:
	    col_ind             = int(num_cols * ((role + 1) / numParties))
	    read_cols           = raisin_cols[:col_ind]
	    readColInds.append([0, col_ind])
	# Parties in the middle
	elif role == 1:
	    col_ind_start       = int(num_cols * (role / numParties))
	    col_ind_end         = int(num_cols * ((role + 1) / numParties))
	    read_cols           = raisin_cols[col_ind_start:col_ind_end]
	    readColInds.append([col_ind_start, col_ind_end])
	# Last party
	elif role == 2:
	    col_ind_start       = int(num_cols * (role / numParties))
	    read_cols           = raisin_cols[col_ind_start:]
	    readColInds.append([col_ind_start, num_cols])


df_raisin.set_axis(list(range(0, len(df_raisin))))
scores_tmp 		= df_raisin * qw
# expected_scores = scores_tmp.sum(axis=1).sort_values(ascending=False)[:k]




