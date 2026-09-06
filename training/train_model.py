import os
import json
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from torchvision import transforms, models
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

# 2. Architecture basée sur MobileNetV2 pour une robustesse accrue face aux reflets
class SealVisionModel(nn.Module):
    def __init__(self, output_dim=51):
        super(SealVisionModel, self).__init__()
        # Chargement de MobileNetV2 pré-entraîné comme extracteur de caractéristiques
        backbone = models.mobilenet_v2(weights=models.MobileNet_V2_Weights.DEFAULT)
        self.features = backbone.features
        
        self.pool = nn.AdaptiveAvgPool2d((1, 1))
        
        # Classifieur dense avec Dropout pour stabiliser la prédiction des bits
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Dropout(0.3),
            nn.Linear(1280, 256), # 1280 canaux de sortie pour MobileNetV2
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, output_dim),
            nn.Sigmoid() # Sortie entre 0 et 1 pour chaque bit (binaire)
        )

    def forward(self, x):
        x = self.features(x)
        x = self.pool(x)
        x = self.classifier(x)
        return x

# 3. Fonction principale d'entraînement
def train():
    manifest_path = '../dataset_output/manifest.json'
    images_dir = '../dataset_output/images'
    
    # Prétraitement enrichi avec des augmentations pour simuler les reflets et variations d'éclairage
    transform = transforms.Compose([
        transforms.Resize((224, 224)),
        # Simulation d'éclats lumineux, variations de contraste et légers décalages géométriques
        transforms.ColorJitter(brightness=0.3, contrast=0.3, saturation=0.2),
        transforms.RandomAffine(degrees=10, translate=(0.05, 0.05), scale=(0.95, 1.05)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
    ])

    print("📦 Chargement du dataset avec augmentations robustes...")
    dataset = SealDataset(manifest_path, images_dir, transform=transform)
    dataloader = DataLoader(dataset, batch_size=16, shuffle=True)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"🚀 Utilisation du processeur/accélérateur : {device}")

    model = SealVisionModel(output_dim=51).to(device)
    
    # Fonction de coût et optimiseur avec un taux d'apprentissage adapté au fine-tuning
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.0005)

    epochs = 15
    print(f"🔄 Début de l'entraînement optimisé pour {epochs} époques...")

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
    print("✅ Modèle robuste entraîné et sauvegardé avec succès dans models/seal_vision_model.pth !")

if __name__ == '__main__':
    train()