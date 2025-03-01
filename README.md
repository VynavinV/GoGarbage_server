# <div align="center">Flask Server and API for GoGarbage</div>

## Summary

This project is the source code needed to host the python flask server for GoGarbage. It includes all necessary AI features and API endpoints required to communicate from the GoGarbage mobile app.

## Features

- User authentication (email/password and Google OAuth)
- Image capture and upload for garbage detection
- Leaderboard for top participants
- Reporting and cleaning of garbage areas
- Reward system for users

## Setup

1. Create a Python virtual environment

    ```sh
    python3 -m venv env
    source env/bin/activate  # On Windows use `env\Scripts\activate`
    ```

2. Install dependencies

    ```sh
    pip install -r requirements.txt
    ```

3. Set up environment variables

    Create a `.env` file in the root directory and add the following variables:

    ```env
    SECRET_KEY=your_secret_key
    SUPABASE_URL=your_supabase_url
    SUPABASE_KEY=your_supabase_key
    CENTRAL_WALLET_PRIVATE_KEY=your_central_wallet_private_key
    CENTRAL_WALLET_ADDRESS=your_central_wallet_address
    GOOGLE_CLIENT_ID=your_google_client_id
    CLIENT_SECRETS_FILE=path_to_your_client_secrets_file.json
    REDIRECT_URI=your_redirect_uri
    ```

4. Run the Flask server

    ```sh
    python main.py
    ```

## Endpoints

### Authentication

- `/login`: Login with email and password
- `/signup`: Sign up with email and password
- `/logout`: Logout the current user
- `/login-google`: Login with Google OAuth
- `/callback`: Google OAuth callback

### Image Capture and Upload

- `/capture-image`: Capture image page
- `/upload-image`: Upload captured image for garbage detection
- `/clean-garbage`: Report area as cleaned

### Leaderboard

- `/leaderboard`: Get the leaderboard data
- `/add-player`: Add a new player to the leaderboard

### Rewards

- `/rewards`: Get rewards for the user
- `/add-reward`: Add a reward for the user
- `/check-reward`: Check if a reward exists for the user

### Coins

- `/get-unclaimed-coins`: Get unclaimed coins for the user
- `/update-unclaimed-coins`: Update unclaimed coins for the user
- `/add-coins`: Add coins to the user's account
- `/get-coins`: Get the total coins for the user

### Miscellaneous

- `/get-xp`: Get XP for the user
- `/update-xp`: Update XP for the user
- `/validate-key`: Validate the user's key

# <div align="center">Litter Detection with Yolov8</div>
![demo](https://github.com/jeremy-rico/litter-detection/raw/master/assets/litter-detection.gif)
     
## Summary

This is a demo for detecting trash/litter objects with Ultralytics YOLOv8 and the Trash Annotations in Context (TACO) dataset created by Pedro Procenca and Pedro Simoes. Included is an infer and train script for you to do similar experiments to what I did. There are also the results and weights of various training runs in runs/detect/train for you to experiment with or use as pretrained weights.

## INFERENCE

1. Create a Python virtual environment

    ```sh
    python3 -m venv yolov8-env
    source yolov8-env/bin/activate  # On Windows use `yolov8-env\Scripts\activate`
    ```

2. Install ultralytics yolov8

    ```sh
    python3 -m pip install ultralytics
    ```

3. Run infer script

    ```sh
    python3 infer.py src=path/to/your/test/data
    ```

See the ultralytics documentation on yolov8 for more information
https://docs.ultralytics.com/

## TRAINING

1. Download TACO dataset:
https://github.com/pedropro/TACO

Note: You can add more annotated data if you'd like. Just ensure labels are in proper YOLO format

2. Format the dataset

Organize the data into the directory structure below

    ├── yolov8
         └── train
              └── images (folder including all training images)
              └── labels (folder including all training labels)
         └── test
               └── images (folder including all testing images)
               └── labels (folder including all testing labels)
         └── valid
              └── images (folder including all testing images)
              └── labels (folder including all testing labels)

3. Create custom data yaml. 
I've provided the one I created for TACO. You will need to change the path at the top to your local TACO directory. It should look something like this:

custom_data.yaml:

    path:  (dataset directory path)
    train: (Complete path to dataset train folder)
    test: (Complete path to dataset test folder) 
    valid: (Complete path to dataset valid folder)

    #Classes
    nc: # replace according to your number of classes

    #classes names
    #replace all class names list with your classes names
    names: ['put', 'classes', 'here']

4. Run train.py

    ```sh
    python3 train.py
    ```

## Sources

Ultralytics Yolov8:

https://github.com/ultralytics/ultralytics

Trash Annotations in Context (TACO):

https://github.com/pedropro/TACO

http://tacodataset.org/
