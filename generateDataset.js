const fs = require('fs');
const path = require('path');
const { createCanvas, loadImage } = require('canvas');
const SealRenderer = require('./engine/sealRenderer');

// Configuration du Dataset
const TOTAL_SAMPLES = 500; // Nombre d'images synthétiques à générer pour l'entraînement
const OUTPUT_DIR = path.join(__dirname, 'dataset_output');
const IMAGES_DIR = path.join(OUTPUT_DIR, 'images');
const MANIFEST_PATH = path.join(OUTPUT_DIR, 'manifest.json');

// Création des dossiers de sortie
if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });
if (!fs.existsSync(IMAGES_DIR)) fs.mkdirSync(IMAGES_DIR, { recursive: true });

/**
 * Applique des altérations aléatoires sur l'image pour simuler une photo de smartphone sur le terrain
 */
async function augmentImage(imageBuffer) {
    const img = await loadImage(imageBuffer);
    const canvas = createCanvas(img.width, img.height);
    const ctx = canvas.getContext('2d');

    // Fond aléatoire (simuler un carton ou un emballage texturé/coloré)
    const bgColors = ['#FFFFFF', '#F1F5F9', '#E2E8F0', '#CBD5E1', '#FEF3C7', '#E0F2FE'];
    const randomBg = bgColors[Math.floor(Math.random() * bgColors.length)];
    
    ctx.fillStyle = randomBg;
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.save();

    // Simulation de l'angle de prise de vue (légère rotation - ex: entre -8° et +8°)
    const angle = (Math.random() * 16 - 8) * (Math.PI / 180);
    ctx.translate(canvas.width / 2, canvas.height / 2);
    ctx.rotate(angle);

    // Légère variation d'échelle (zoom in / zoom out)
    const scale = 0.85 + Math.random() * 0.25;
    ctx.scale(scale, scale);

    ctx.drawImage(img, -img.width / 2, -img.height / 2);
    ctx.restore();

    // Simulation de bruit ou de luminosité via des passes de filtre légères
    // (Ici on simplifie en ajustant la transparence ou en exportant en JPEG compressé)
    return canvas.toBuffer('image/jpeg', { quality: 0.75 + Math.random() * 0.25 });
}

async function runDatasetGeneration() {
    console.log(`🚀 [DATASET] Début de la génération de ${TOTAL_SAMPLES} échantillons synthétiques...`);
    const manifest = [];

    for (let i = 1; i <= TOTAL_SAMPLES; i++) {
        const batchCode = `LOT-AI-${2026}-${String(i).padStart(4, '0')}`;
        
        try {
            // 1. Génération de la matrice intelligente via le protocole existant
            const smartPayload = SealRenderer.deriveVisualBits ? {
                visualBits: SealRenderer.deriveVisualBits(batchCode)
            } : {};

            // 2. Rendu propre du sceau
            const rawBuffer = await SealRenderer.renderSealToBuffer({
                lot: batchCode,
                ...smartPayload
            }, {
                width: 600,
                height: 600
            });

            // 3. Augmentation des données (bruit, angle, compression)
            const finalImageBuffer = await augmentImage(rawBuffer);

            // 4. Sauvegarde du fichier image
            const imageName = `seal_${i.toString().padStart(4, '0')}.jpg`;
            const imagePath = path.join(IMAGES_DIR, imageName);
            fs.writeFileSync(imagePath, finalImageBuffer);

            // 5. Récupération des 51 bits de vérité terrain (Ground Truth)
            const groundTruthBits = SealRenderer.deriveVisualBits(batchCode);

            manifest.push({
                id: i,
                filename: imageName,
                lot: batchCode,
                groundTruthBits: groundTruthBits, // La cible exacte que l'IA devra prédire
                metadata: {
                    generatedAt: new Date().toISOString()
                }
            });

            if (i % 50 === 0) {
                console.log(`📦 [PROGRES] ${i}/${TOTAL_SAMPLES} sceaux générés avec succès...`);
            }
        } catch (err) {
            console.error(`❌ Erreur sur l'échantillon ${i} (${batchCode}) :`, err.message);
        }
    }

    // Écriture du manifest global d'entraînement
    fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2));
    console.log(`✅ [SUCCÈS] Dataset généré avec succès ! Manifest enregistré dans : ${MANIFEST_PATH}`);
}

runDatasetGeneration();