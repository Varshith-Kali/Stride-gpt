/**
 * useImageUpload — session-only image state management.
 *
 * Images are held exclusively in React useState. They are never written to
 * localStorage, sessionStorage, IndexedDB, cookies, or any server. They are
 * automatically discarded when the browser tab is closed or refreshed.
 *
 * Limits (enforced client-side; mirrored server-side in validation.ts):
 *   - Max 5 images per session
 *   - Max 4 MB per image (raw file size)
 *   - Allowed MIME types: image/png, image/jpeg, image/webp
 */
"use client";

import { useState, useCallback } from "react";

export interface UploadedImage {
  /** Stable client-side ID for keying React lists and removal. */
  id: string;
  /** Original filename — display only. */
  name: string;
  /** Human-readable size string, e.g. "1.2 MB". */
  sizeLabel: string;
  /** MIME type — one of the ALLOWED_TYPES below. */
  mimeType: "image/png" | "image/jpeg" | "image/webp";
  /** Full data-URL (base64). Sent to the LLM as multimodal context. */
  dataUrl: string;
  /** Object URL for thumbnail preview (revoked on removal). */
  previewUrl: string;
}

const ALLOWED_TYPES = new Set(["image/png", "image/jpeg", "image/webp"]);
const MAX_IMAGES = 5;
const MAX_BYTES = 4 * 1024 * 1024; // 4 MB

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

let _idCounter = 0;
function nextId(): string {
  return `img_${Date.now()}_${_idCounter++}`;
}

export interface UseImageUploadResult {
  images: UploadedImage[];
  /** Add one or more files. Returns user-facing error messages for rejections. */
  addFiles: (files: FileList | File[]) => Promise<string[]>;
  /** Remove a single image by ID, revoking its object URL. */
  removeImage: (id: string) => void;
  /** Remove all images, revoking all object URLs. */
  clearAll: () => void;
  /** True when the maximum image count is reached. */
  isFull: boolean;
}

export function useImageUpload(): UseImageUploadResult {
  const [images, setImages] = useState<UploadedImage[]>([]);

  const addFiles = useCallback(
    async (files: FileList | File[]): Promise<string[]> => {
      const fileArray = Array.from(files);
      const errors: string[] = [];

      // Snapshot current count to enforce limit across the batch
      let pending = 0;
      setImages((prev) => {
        pending = prev.length;
        return prev;
      });

      const toAdd: UploadedImage[] = [];

      for (const file of fileArray) {
        if (pending + toAdd.length >= MAX_IMAGES) {
          errors.push(`Maximum ${MAX_IMAGES} images allowed — "${file.name}" skipped.`);
          continue;
        }
        if (!ALLOWED_TYPES.has(file.type)) {
          errors.push(`"${file.name}" is not a supported format (PNG, JPEG, WebP only).`);
          continue;
        }
        if (file.size > MAX_BYTES) {
          errors.push(`"${file.name}" exceeds the 4 MB limit (${formatBytes(file.size)}).`);
          continue;
        }

        // Read as base64 data-URL
        const dataUrl = await new Promise<string>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => resolve(reader.result as string);
          reader.onerror = () => reject(new Error("FileReader error"));
          reader.readAsDataURL(file);
        }).catch(() => null);

        if (!dataUrl) {
          errors.push(`Failed to read "${file.name}".`);
          continue;
        }

        const previewUrl = URL.createObjectURL(file);
        toAdd.push({
          id: nextId(),
          name: file.name,
          sizeLabel: formatBytes(file.size),
          mimeType: file.type as UploadedImage["mimeType"],
          dataUrl,
          previewUrl,
        });
      }

      if (toAdd.length > 0) {
        setImages((prev) => [...prev, ...toAdd].slice(0, MAX_IMAGES));
      }

      return errors;
    },
    []
  );

  const removeImage = useCallback((id: string) => {
    setImages((prev) => {
      const img = prev.find((i) => i.id === id);
      if (img) URL.revokeObjectURL(img.previewUrl);
      return prev.filter((i) => i.id !== id);
    });
  }, []);

  const clearAll = useCallback(() => {
    setImages((prev) => {
      prev.forEach((i) => URL.revokeObjectURL(i.previewUrl));
      return [];
    });
  }, []);

  return {
    images,
    addFiles,
    removeImage,
    clearAll,
    isFull: images.length >= MAX_IMAGES,
  };
}
