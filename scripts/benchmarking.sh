#!/bin/bash

readonly TIMESTAMP=$(date +%s)

readonly ITERATIONS=25
readonly OUTPUT_DIR="benchmarks"
readonly EXECUTABLE="../build/rkvac-protocol-multos"

# check if output dir exists
[ ! -d ${OUTPUT_DIR} ] && mkdir ${OUTPUT_DIR}

# check if the executable exists
[ ! -f ${EXECUTABLE} ] && exit

for attributes in {1..9}
do
  for disclosed_attributes in {0..9}
  do
    if [ ${disclosed_attributes} -le ${attributes} ]
    then
      computation_average=0
      communication_average=0
      for i in $(seq 1 ${ITERATIONS})
      do
        echo "[${disclosed_attributes}/${attributes}] Running ${i}/${ITERATIONS}..."
        elapsed_time_data=$(${EXECUTABLE} --attributes "${attributes}" --disclosed-attributes "${disclosed_attributes}" | grep -a "Elapsed time")

        # raw times
        computation_time=$(echo "${elapsed_time_data}" | grep "compute_proof_of_knowledge" | cut -d' ' -f6)
        communication_time=$(echo "${elapsed_time_data}" | grep "communication_proof_of_knowledge" | cut -d' ' -f6 | tr '\n' ';' | rev | cut -c 2- | rev)
        total_communication_time=$(echo "${communication_time}" | tr ';' '+' | bc | sed 's/^\./0./')
        computation_communication_time=$(echo "scale=6; ${computation_time}+${total_communication_time}" | bc)
        echo "${attributes}/${disclosed_attributes}: ${computation_communication_time};${computation_time};${total_communication_time};${communication_time}" >>"${OUTPUT_DIR}/${TIMESTAMP}_raw.txt"

        # partial average
        computation_average=$(echo "scale=6; ${computation_average}+${computation_time}" | bc)
        communication_average=$(echo "scale=6; ${communication_average}+${total_communication_time}" | bc)
      done

      # average times
      computation_average=$(echo "scale=6; ${computation_average}/${ITERATIONS}" | bc | sed 's/^\./0./')
      communication_average=$(echo "scale=6; ${communication_average}/${ITERATIONS}" | bc | sed 's/^\./0./')
      computation_communication_average=$(echo "scale=6; ${computation_average}+${communication_average}" | bc | sed 's/^\./0./')
      echo "${attributes}/${disclosed_attributes}: ${computation_communication_average};${computation_average};${communication_average}" >>"${OUTPUT_DIR}/${TIMESTAMP}_csv.txt"
    fi
  done
done
