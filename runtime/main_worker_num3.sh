# Number of runs...
for r in 1 #{1..3} #1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
do
	echo "Starting run = $r"
	for k in 4 #2 4 8 16 32 64 128 256
	do
		for dataset in 'raisin' 'housing' 'dry_bean' 'wine_quality' 'shuttle'
		do
			if [ $dataset = 'raisin' ]; then
				echo "Starting k = $k and database = $dataset"
				python3.11 src/worker.py $dataset '1, 1, 1, 1, 1, 1, 1, 1, 1' $k 3 3 'vertical' 'secure' 3 'localhost,localhost,localhost,localhost,localhost,localhost,localhost'
			elif [ $dataset = 'housing' ]; then
				echo "Starting k = $k and database = $dataset"
				python3.11 src/worker.py $dataset '1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1' $k 3 3 'vertical' 'secure' 3 'localhost,localhost,localhost,localhost,localhost,localhost,localhost'
			elif [ $dataset = 'dry_bean' ]; then
				echo "Starting k = $k and database = $dataset"
				python3.11 src/worker.py $dataset '1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1' $k 3 3 'vertical' 'secure' 3 'localhost,localhost,localhost,localhost,localhost,localhost,localhost'
			elif [ $dataset = 'wine_quality' ]; then
				echo "Starting k = $k and database = $dataset"
				python3.11 src/worker.py $dataset '1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1' $k 3 3 'vertical' 'secure' 3 'localhost,localhost,localhost,localhost,localhost,localhost,localhost'
			elif [ $dataset = 'shuttle' ]; then
				echo "Starting k = $k and database = $dataset"
				python3.11 src/worker.py $dataset '1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1' $k 3 3 'vertical' 'secure' 3 'localhost,localhost,localhost,localhost,localhost,localhost,localhost'
			fi
		done
	done
done


