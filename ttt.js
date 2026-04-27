
exports.uploadDocuments = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    if (!data.auth.token.email_verified === true) {
      throw new HttpsError(
        "unauthenticated",
        "You must be signed in to call this function."
      );
    }

    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set"
      );
    }

    validateData(data.data, [
      { key: "customerId", message: "Customer ID is required" },
      { key: "documentId", message: "Document ID is required" },
      { key: "fileBase64", message: "File content in base64 is required" },
      { key: "fileName", message: "File name is required" },
    ]);

    const {
      customerId,
      documentId,
      fileBase64,
      fileName,
      textData = "",
    } = data.data;

    const url = `https://api.sandbox.getanchor.co/api/v1/documents/upload-document/${encodeURIComponent(
      customerId.trim()
    )}/${encodeURIComponent(documentId.trim())}`;

    const fileBuffer = Buffer.from(fileBase64, "base64");

    console.log("=== uploadDocuments REQUEST ===", {
      customerId: customerId.trim(),
      documentId: documentId.trim(),
      fileName,
      fileSizeBytes: fileBuffer.length,
      hasTextData: !!textData,
      textDataLength: textData.length,
      url,
    });

    const FormData = require("form-data");
    const form = new FormData();
    form.append("fileData", fileBuffer, { filename: fileName });

    if (textData) {
      form.append("textData", textData);
    }

    const headers = {
      ...form.getHeaders(),
      accept: "application/json",
      "x-anchor-key": secretKey,
    };

    console.log("Request headers (redacted):", {
      ...headers,
      "x-anchor-key": "[REDACTED]",
    });

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: form,
    });

    let responseBody;
    try {
      responseBody = await response.json();
    } catch (e) {
      responseBody = await response.text();
    }

    console.log("=== GetAnchor API RESPONSE ===", {
      status: response.status,
      statusText: response.statusText,
      body: responseBody,
    });

    if (!response.ok) {
      throw new HttpsError(
        "internal",
        `Anchor API error: ${response.status} ${
          response.statusText
        }\nResponse body: ${JSON.stringify(responseBody)}`
      );
    }

    return responseBody;
  }
);