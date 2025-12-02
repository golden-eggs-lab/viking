# python __main__.py 'dataset' 'query', 'k'
# Dataset options: 'dry_bean', 'housing', 'raisin'
# Query weights: '[]', '[]', '[]'
# k = [1 - 256]

# Test...
# python __main__.py 'housing', '0.1, 0.25, 0.1, 0.2, 0.5, 0.3, 0.6, 0.2, 0.15', 2

for r in 1 2
do
	echo "Starting run = $r"
	for k in 2 4 8 16 32 64 #128 256
	do
		for dataset in 'housing' 'dry_bean' 'raisin'
		do
			if [ $dataset = 'housing' ]; then
				echo "Starting k = $k and database = $dataset"
				python __main__.py $dataset '-212, 71, 88, 66898, 10965, 60708, 10348, 26, 850684' $k 2 2
			# elif [ $dataset = 'dry_bean' ]; then
			# 	echo "Starting k = $k and database = $dataset"
			# 	python __main__.py $dataset '1.92, 11, 30, 49, 63, 136, 1.92, 3.83, 136, 103, 116, 128, 155, 59, 15, 9.58' $k
			elif [ $dataset = 'raisin' ]; then
			echo "Starting k = $k and database = $dataset"
			python __main__.py $dataset '0.77, 157, 267, 86947, 0.75, 97144, 58' $k 2 2
			fi
		done
	done
done

