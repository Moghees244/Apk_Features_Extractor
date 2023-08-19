import os
import re
import subprocess
import pandas as pd
from datetime import datetime
from androguard.core.bytecodes import apk


# read all permissions from file and make a list of it
def get_feature_list(file_path):
    with open(file_path, "r") as features_file:
        features = features_file.readlines()
    features = [word.strip() for word in features]
    return features


# feature extraction of all apks
def extract_features(dataframe):
    total_samples, samples_extracted = len(os.listdir(apks_path)), 0
    print(f"--- Extracting Features From {total_samples} Samples ---")

    app_data = {}
    # Traverse each apk file in folder
    for file_name in os.listdir(apks_path):
        # check if the file exists
        if os.path.isfile(os.path.join(apks_path, file_name)):
            # Decompile it
            print(f"\n-- Extracting Features From {file_name} --")
            try:
                app = apk.APK(os.path.join(apks_path, file_name))

                # extract AndroidManifest.xml file
                xml = app.get_android_manifest_axml().get_xml()
                xml = str(xml)
            except:
                print(f"*** {file_name} is Not Extracted. ***")
                samples_extracted += 1
                continue

            # Extracting features from AndroidManifest.xml and One-Hot Encoding the features in list in sequence
            for fea in manifest_features:
                if fea in xml:
                    app_data[fea] = 1
                else:
                    app_data[fea] = 0

            print("Permissions Extracted")
            # Extracting api calls from source code of apk
            extracted_api_calls = extract_api_calls(file_name)

            if extracted_api_calls is None:
                samples_extracted += 1
                continue

            # One-Hot Encoding api calls
            for api_call in api_calls:
                if api_call in extracted_api_calls:
                    app_data[api_call] = 1
                else:
                    app_data[api_call] = 0

            # append list to data frame
            app_data['Name'] = file_name
            app_data['Class'] = 'M'
            dataframe = dataframe._append(app_data, ignore_index=True)
            samples_extracted += 1

            # Stats
            print(f"\n-- Features Extracted From {samples_extracted}/{total_samples} Samples. --\n")
            if samples_extracted % 10 == 0:
                dataframe.to_csv("../Datasets/Malware.csv", index=False)

    return dataframe


def find_java_files():
    java_files = []
    # Finding and saving paths of all .java files in source code of apk
    for folder_name, subfolders, filenames in os.walk(source_code_path):
        for filename in filenames:
            if filename.endswith('.java'):
                java_files.append(os.path.join(folder_name, filename))
    return java_files


def extract_api_calls(filename):
    apk_api_calls = []
    print("Getting Source Code")
    try:
        # Getting apk source code and saving in a folder
        command = ["jadx", "-d", source_code_path, os.path.join(apks_path, filename)]
        with open(os.devnull, "w") as devnull:
            subprocess.run(command, stdout=devnull, stderr=subprocess.STDOUT)

        print("Analysing Source Code")
        # Finding api calls from all java files
        for file in find_java_files():
            with open(file, 'r') as source_file:
                code = source_file.read()
                for api_call in api_calls:
                    match = re.match(r"(?P<class>\w+)\.(?P<method>\w+)", api_call)
                    method = match.group("method") + '('
                    if match.group("class") in code and method in code:
                        apk_api_calls.append(api_call)

    except:
        print(f"*** {filename} Api Calls Not Extracted. ***")
        return None

    # Deleting the source code
    subprocess.run(["rm", "-r", source_code_path])
    return apk_api_calls


if __name__ == "__main__":
    print("Start Time : ", datetime.now().strftime("%H:%M:%S"))
    # Paths
    manifest_features_file_path = '../Features/Selected_Manifest_Features.txt'
    api_calls_file_path = '../Features/Selected_Api_Calls.txt'

    apks_path = "/home/blackcat/Work/FYP/Malware_Detection_System/apks/"
    source_code_path = "/home/blackcat/Work/FYP/Malware_Detection_System/output"

    # List of permissions
    manifest_features = get_feature_list(manifest_features_file_path)
    api_calls = get_feature_list(api_calls_file_path)

    all_features = manifest_features + api_calls
    all_features.insert(0, 'Name')

    # Dataframe to store features of apps
    dataset = pd.DataFrame(columns=all_features)

    # Storing features of all apps in dataframe
    dataset = extract_features(dataset)

    # Saving all features in .csv file
    dataset.to_csv("../Datasets/Malware.csv", index=False)

    print("End Time : ", datetime.now().strftime("%H:%M:%S"))
    print("<--- Task Completed Successfully ! -->")
