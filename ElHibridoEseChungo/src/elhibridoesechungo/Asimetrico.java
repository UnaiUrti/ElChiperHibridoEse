/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package elhibridoesechungo;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Usuario
 */
public class Asimetrico {
    
    /**
     * Retorna el contenido de un fichero
     *
     * @param path Path del fichero
     * @return El texto del fichero
     */
    private static byte[] fileReader(String path) {
        byte ret[] = null;
        File file = new File(path);
        try {
            ret = Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ret;
    }

    private static PublicKey readPublicKey() {

        PublicKey pubKey = null;

        try {
            // Leemos el texto de la clave pública del archivo
            byte[] encPubKey = fileReader("./src/elhibridoesechungo/ClavePublica.key");

            // Creamos una especificación de clave pública codificada
            X509EncodedKeySpec encPubKeySpec = new X509EncodedKeySpec(encPubKey);

            // Obtenemos la fábrica de claves del algoritmo especificado y generar el objeto de clave pública de acuerdo con la especificación de clave pública codificada
            pubKey = KeyFactory.getInstance("RSA").generatePublic(encPubKeySpec);

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        }

        return pubKey;
    }

    private static PrivateKey readPrivateKey() {

        PrivateKey priKey = null;
        
        try {
            // Leemos el texto de la clave privada del archivo
            byte[] encPriKey = fileReader("./src/elhibridoesechungo/ClavePrivada.key");

            // Creamos una especificación de clave privada codificada
            PKCS8EncodedKeySpec encPriKeySpec = new PKCS8EncodedKeySpec(encPriKey);

            // Obtenemos la fábrica de claves del algoritmo especificado y generar el objeto de clave privada de acuerdo con la especificación de clave privada codificada
            priKey = KeyFactory.getInstance("RSA").generatePrivate(encPriKeySpec);

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        }

        return priKey;
    }

    private static byte[] cifradoPublico(String mensaje){
        
        byte[] cifrao = null;
        
        try {
            // Obtenemos el cifrado del algoritmo especificado
            Cipher Asimetrico = Cipher.getInstance("RSA");

            // Inicializamos el cifrado (modelo de descifrado de clave pública)
            Asimetrico.init(Cipher.ENCRYPT_MODE, readPublicKey());

            // Datos cifrados, devuelve el texto cifrado
            cifrao = Asimetrico.doFinal(mensaje.getBytes());
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return cifrao;
    }
    
    private static byte[] descifradoPrivado(byte[] cifrao){
        
        byte[] descifrao = null;
        
        try {
            // Obtener el cifrado del algoritmo especificado
            Cipher cipher = Cipher.getInstance("RSA");

            // Inicializar el cifrado (modelo de descifrado de clave privada)
            cipher.init(Cipher.DECRYPT_MODE, readPrivateKey());

            // Descifrar los datos, devolver el texto plano descifrado
            descifrao = cipher.doFinal(cifrao);
            
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(Asimetrico.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return descifrao;
    }
    
}
