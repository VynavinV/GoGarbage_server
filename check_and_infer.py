import argparse
import os
import cv2
from ultralytics import YOLO

parser = argparse.ArgumentParser(description="Yolov8 inference script")
parser.add_argument(
    "--model",
    type=str,
    default="runs/detect/train/yolov8s_100epochs/weights/best.pt",
    help="path to yolo weights"
)
parser.add_argument(
    "--source",
    type=str,
    default="0",  # Use the default camera
    help="path to data to infer on or camera index"
)
parser.add_argument(
    "--save",
    action="store_true",
    help="save predictions"
)

image_path = "image.jpg"  # Add this line to specify the image path directly

def run_inference(image_path):
    model = YOLO("runs/detect/train/yolov8s_100epochs/weights/best.pt")
    results = model.predict(source=image_path, save=True)

    total_trash_items = 0  # Initialize counter for trash items

    for result in results:
        frame = result.orig_img
        for box in result.boxes:
            x1, y1, x2, y2 = map(int, box.xyxy[0].tolist())  # Flatten the list
            label = int(box.cls)  # Convert tensor to int
            confidence = float(box.conf)  # Convert tensor to float
            cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 255, 0), 2)
            cv2.putText(frame, f"{label} {confidence:.2f}", (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
            total_trash_items += 1  # Increment counter for each detected item
        
        output_path = os.path.splitext(image_path)[0] + "_detected.jpg"
        cv2.imwrite(output_path, frame)
        return os.path.basename(output_path), total_trash_items  # Return the highlighted image path and garbage amount

if __name__ == "__main__":
    args = parser.parse_args()

    # Use the image_path variable instead of args.source
    if os.path.exists(image_path):
        output_path, total_trash_items = run_inference(image_path)
        print(f"Output saved to {output_path}")
        print(f"Total trash items detected: {total_trash_items}")  # Print the total number of trash items detected
    else:
        print(f"Error: The source file {image_path} does not exist.")

