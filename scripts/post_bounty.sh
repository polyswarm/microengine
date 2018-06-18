#!/usr/bin/env bash

artifact_path=$1

#
# Upload artifacts
#
cmd_upload_artifacts="curl -s -F file=@$artifact_path http://localhost:31337/artifacts"
echo $cmd_upload_artifacts
$cmd_upload_artifacts


# address = "d87e4662653042c5da11711542c11f2c8433612d"
# curl -s -H 'Content-Type: application/json' -d '#{password}' http://localhost:31337/accounts/#{get_address}/unlock
# curl -s -H 'Content-Type: application/json' -d '{\"amount\": \"62500000000000000\", \"uri\": \"#{artifact_upload_result_hash}\", \"duration\": 10}' http://localhost:31337/bounties?account=#{address}"
