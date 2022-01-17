/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package elhibridoesechungo;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Usuario
 */
public class Simetrico {
    
    // Fíjate que el String es de exactamente 16 bytes
    private static byte[] salt = "esta es la salt!".getBytes();

    /**
     * Cifra un texto con AES, modo CBC y padding PKCS5Padding (simétrica) y lo
     * retorna
     *
     * @param clave La clave del usuario
     * @param mensaje El mensaje a cifrar
     * @return Mensaje cifrado
     */
    public String cifrarTexto(String clave, String mensaje) {
        String ret = null;
        KeySpec keySpec = null;
        SecretKeyFactory secretKeyFactory = null;
        try {

            // Obtenemos el keySpec
            keySpec = new PBEKeySpec(clave.toCharArray(), salt, 65536, 128); // AES-128

            // Obtenemos una instancide de SecretKeyFactory con el algoritmo "PBKDF2WithHmacSHA1"
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            // Generamos la clave
            byte[] key = secretKeyFactory.generateSecret(keySpec).getEncoded();

            // Creamos un SecretKey usando la clave + salt
            SecretKey privateKey = new SecretKeySpec(key, 0, key.length, "AES");

            // Obtenemos una instancide de Cipher con el algoritmos que vamos a usar "AES/CBC/PKCS5Padding"
            Cipher cifrao = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Iniciamos el Cipher en ENCRYPT_MODE y le pasamos la clave privada
            cifrao.init(Cipher.ENCRYPT_MODE, privateKey);
            // Le decimos que cifre (método doFinal())
            byte[] encodedMessage = cifrao.doFinal(mensaje.getBytes());

            // Obtenemos el vector CBC del Cipher (método getIV())
            byte[] iv = cifrao.getIV();

            // Guardamos el mensaje codificado: IV (16 bytes) + Mensaje
            byte[] combined = concatArrays(iv, encodedMessage);

            // Escribimos el fichero cifrado 
            fileWriter("./src/elhibridoesechungo/ClaveSimetrica.key", combined);

            // Retornamos el texto cifrado
            ret = new String(encodedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    /**
     * Descifra un texto con AES, modo CBC y padding PKCS5Padding (simétrica) y
     * lo retorna
     *
     * @param clave La clave del usuario
     */
    private String descifrarTexto(String clave) {
        String ret = null;

        // Fichero leído
        byte[] fileContent = fileReader("./src/elhibridoesechungo/ClaveSimetrica.key"); // Path del fichero EjemploAES.dat
        KeySpec keySpec = null;
        SecretKeyFactory secretKeyFactory = null;
        try {
            // Obtenemos el keySpec
            keySpec = new PBEKeySpec(clave.toCharArray(), salt, 65536, 128); // AES-128

            // Obtenemos una instancide de SecretKeyFactory con el algoritmo "PBKDF2WithHmacSHA1"
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            // Generamos la clave
            byte[] key = secretKeyFactory.generateSecret(keySpec).getEncoded();

            // Creamos un SecretKey usando la clave + salt
            SecretKey privateKey = new SecretKeySpec(key, 0, key.length, "AES");

            // Obtenemos una instancide de Cipher con el algoritmos que vamos a usar "AES/CBC/PKCS5Padding"
            Cipher chiper = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Leemos el fichero codificado 
            IvParameterSpec ivParam = new IvParameterSpec(Arrays.copyOfRange(fileContent, 0, 16));

            // Iniciamos el Cipher en ENCRYPT_MODE y le pasamos la clave privada y el ivParam
            
            chiper.init(Cipher.DECRYPT_MODE, privateKey, ivParam);
            
            // Le decimos que descifre
            byte[] decodedMessage = chiper.doFinal(Arrays.copyOfRange(fileContent, 16, fileContent.length));
            
            // Texto descifrado
            ret = new String(decodedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }
    
    /**
     * Retorna una concatenaci�n de ambos arrays
     *
     * @param array1
     * @param array2
     * @return Concatenaci�n de ambos arrays
     */
    private byte[] concatArrays(byte[] array1, byte[] array2) {
        byte[] ret = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, ret, 0, array1.length);
        System.arraycopy(array2, 0, ret, array1.length, array2.length);
        return ret;
    }

    /**
     * Escribe un fichero
     *
     * @param path Path del fichero
     * @param text Texto a escibir
     */
    private void fileWriter(String path, byte[] text) {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(text);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Retorna el contenido de un fichero
     *
     * @param path Path del fichero
     * @return El texto del fichero
     */
    private byte[] fileReader(String path) {
        byte ret[] = null;
        File file = new File(path);
        try {
            ret = Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ret;
    }
    
}
