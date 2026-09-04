import os
import json
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from torchvision import transforms
from PIL import Image

# 1. Définition du Dataset PyTorch pour charger nos images et leurs 51 bits
class SealDataset(Dataset):
    def __init__(self, manifest_path, images_dir, transform=None):
        with open(manifest_path, 'r', encoding='utf-8') as f:
            self.manifest = json.load(f)
        self.images_dir = images_dir
        self.transform = transform

    def __len__(self):
        return len(self.manifest)

    def __getitem__(self, idx):
        item = self.manifest[idx]
        img_path = os.path.join(self.images_dir, item['filename'])
        image = Image.open(img_path).convert('RGB')
        
        # Transformation des bits en tenseur PyTorch
        bits_str = item['groundTruthBits'] # ex: "10110..."
        bits_tensor = torch.tensor([float(b) for b in bits_str], dtype=torch.float32)

        if self.transform:
            image = self.transform(image)

        return image, bits_tensor

# 2. Architecture d'un Réseau de Neurones Convolutif (CNN) léger pour la vision des sceaux
class SealVisionModel(nn.Module):
    def __init__(self, output_dim=51):
        super(SealVisionModel, self).__init__()
        self.features = nn.Sequential(
            nn.Conv2d(3, 16, kernel_size=3, stride=1, padding=1), 
            nn.ReLU(),
            nn.MaxPool2d(2, 2),                           
            
            nn.Conv2d(16, 32, kernel_size=3, stride=1, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2, 2),                           
            
            nn.Conv2d(32, 64, kernel_size=3, stride=1, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2, 2),                           
            
            nn.AdaptiveAvgPool2d((4, 4))                  
        )
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(64 * 4 * 4, 128),
            nn.ReLU(),
            nn.Linear(128, output_dim),
            nn.Sigmoid() # Sortie entre 0 et 1 pour chaque bit (binaire)
        )

    def forward(self, x):
        x = self.features(x)
        x = self.classifier(x)
        return x

# 3. Fonction principale d'entraînement
def train():
    # Chemins corrigés depuis le dossier backend/training vers la racine backend
    manifest_path = '../dataset_output/manifest.json'
    images_dir = '../dataset_output/images'
    
    # Prétraitement des images pour le modèle (redimensionnement en 224x224 et normalisation)
    transform = transforms.Compose([
        transforms.Resize((224, 224)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
    ])

    print("📦 Chargement du dataset...")
    dataset = SealDataset(manifest_path, images_dir, transform=transform)
    dataloader = DataLoader(dataset, batch_size=16, shuffle=True)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"🚀 Utilisation du processeur/accélérateur : {device}")

    model = SealVisionModel(output_dim=51).to(device)
    
    # Fonction de coût (Binary Cross Entropy pour prédire chaque bit de manière indépendante)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    epochs = 10
    print(f"🔄 Début de l'entraînement pour {epochs} époques...")

    for epoch in range(epochs):
        model.train()
        running_loss = 0.0
        for images, labels in dataloader:
            images, labels = images.to(device), labels.to(device)

            optimizer.zero_grad()
            outputs = model(images)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()

            running_loss += loss.item() * images.size(0)

        epoch_loss = running_loss / len(dataset)
        print(f"Epoch [{epoch+1}/{epochs}], Loss: {epoch_loss:.4f}")

    # Sauvegarde du modèle entraîné
    os.makedirs('models', exist_ok=True)
    torch.save(model.state_dict(), 'models/seal_vision_model.pth')
    print("✅ Modèle souverain entraîné et sauvegardé avec succès dans models/seal_vision_model.pth !")

if __name__ == '__main__':
    train()