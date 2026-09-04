import os
import json
import sys
import torch
from torchvision import transforms
from PIL import Image
from train_model import SealVisionModel  # Importation de l'architecture définie précédemment

def predict_seal(image_path, silent=False):
    if not silent:
        print("======================================================")
        print("ANOR AI - Inférence et Test du Sceau Souverain")
        print("======================================================")

    # 1. Configuration du device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    if not silent:
        print(f"🚀 Utilisation du processeur/accélérateur : {device}")

    # 2. Chargement du modèle entraîné
    model_path = 'models/seal_vision_model.pth'
    if not os.path.exists(model_path):
        if not silent:
            print(f"[ERREUR] Le modèle entraîné '{model_path}' est introuvable.")
        return None

    model = SealVisionModel(output_dim=51)
    model.load_state_dict(torch.load(model_path, map_location=device))
    model = model.to(device)
    model.eval()
    
    if not silent:
        print("📦 Modèle chargé avec succès depuis models/seal_vision_model.pth")

    # 3. Prétraitement de l'image cible
    transform = transforms.Compose([
        transforms.Resize((224, 224)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
    ])

    if not os.path.exists(image_path):
        if not silent:
            print(f"[ERREUR] L'image cible '{image_path}' est introuvable.")
        return None

    image = Image.open(image_path).convert('RGB')
    input_tensor = transform(image).unsqueeze(0).to(device)

    # 4. Prédiction (Inférence)
    with torch.no_grad():
        outputs = model(input_tensor)
        predicted_bits_tensor = (outputs >= 0.5).float()
        predicted_bits_str = "".join([str(int(b.item())) for b in predicted_bits_tensor[0]])

    if not silent:
        print("\n------------------------------------------------------")
        print(f"🖼️ Image analysée : {image_path}")
        print(f"🔑 Matrice de 51 bits prédite par l'IA :")
        print(predicted_bits_str)
        print("------------------------------------------------------")
    
    return predicted_bits_str

if __name__ == '__main__':
    # Si un argument (le chemin de l'image) est passé par Node.js via execSync
    if len(sys.argv) > 1:
        target_image = sys.argv[1]
        # On active le mode silencieux pour ne retourner que les 51 bits exacts
        result = predict_seal(target_image, silent=True)
        if result:
            print(result)
    else:
        # Mode test classique par défaut
        sample_image = '../dataset_output/images/sceau_1.png' 
        try:
            with open('../dataset_output/manifest.json', 'r', encoding='utf-8') as f:
                manifest = json.load(f)
                if manifest and len(manifest) > 0:
                    sample_image = os.path.join('../dataset_output/images', manifest[0]['filename'])
        except Exception:
            pass
        predict_seal(sample_image, silent=False)