/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package kedamosServerSide.entities;

import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Objects;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.MapsId;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;

/**
 * Entidad revisar que se crea con la relacion de EventManager y Event
 * @author UnaiUrtiaga
 */
@Entity
public class Revise implements Serializable {

    private static final long serialVersionUID = 1L;
    
    /**
     * Grupo de IDs cogidas de las entidades EventManager(User) y Event
     */
    @EmbeddedId
    private ReviseId revise_id;
    
    /**
     * Atributo tipo fecha que guarda cuando ha sido revisado el evento
     */
    @NotNull
    @Temporal(TemporalType.TIMESTAMP)
    private Timestamp revisionDate;
    
    /**
     * Atributo primario que guarda el manager que ha revisado el evento
     */
    @MapsId("user_id")
    @ManyToOne
    private EventManager reviser;
    
    /**
     * Atributo primario que guarda el evento que ha sido revisado
     */
    @MapsId("event_id")
    @ManyToOne
    private Event event;

    /**
     * Get de los IDs de la revision
     * @return Devuelve la clase ReviseId que contiene todos los IDs de la entidad
     */
    public ReviseId getId() {
        return revise_id;
    }

    /**
     * Set de los IDs de la revision
     * @param id 
     */
    public void setId(Long id) {
        this.revise_id = revise_id;
    }

    /**
     * Get de la fecha de revision
     * @return Devuelve la fecha de la revision
     */
    public Timestamp getRevisionDate() {
        return revisionDate;
    }

    /**
     * Set de la fecha de revision
     * @param revisionDate 
     */
    public void setRevisionDate(Timestamp revisionDate) {
        this.revisionDate = revisionDate;
    }

    /**
     * Get del manager que ha revisado el evento
     * @return Devuelve el manager
     */
    public EventManager getReviser() {
        return reviser;
    }

    /**
     * Set del manager que ha revisado el evento
     * @param reviser 
     */
    public void setReviser(EventManager reviser) {
        this.reviser = reviser;
    }

    /**
     * Get del evento que ha sido revisado
     * @return Devuelve el evento
     */
    public Event getEvent() {
        return event;
    }

    /**
     * Set del evento que ha sido revisado
     * @param event 
     */
    public void setEvent(Event event) {
        this.event = event;
    }

    /**
     * HashCode de todos los atributos
     * @return Devuelve un HashCode
     */
    @Override    
    public int hashCode() {
        int hash = 0;
        hash += (revise_id != null ? revise_id.hashCode() : 0);
        return hash;
    }

    /**
     * Equals que comprueba el valor de dos revisiones
     * @param obj
     * @return Devuelve un booleano
     */
    @Override
    public boolean equals(Object object) {
        if (!(object instanceof Revise)){
            return false;
        }
        Revise other = (Revise) object;
        if ((this.revise_id == null && other.revise_id != null) || (this.revise_id != null && !this.revise_id.equals(other.revise_id))){
            return false;
        }
        return true;
    }

    /**
     * ToString para crear un string con todos los datos de la revision
     * @return Devuelve los datos de la revision
     */
    @Override
    public String toString() {
        return "Revise{" + "revise_id=" + revise_id + ", reviseDate=" + revisionDate + ", reviser=" + reviser + ", event=" + event + '}';
    }

    
    
}