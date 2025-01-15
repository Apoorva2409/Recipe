package com.example.demo.model;
import jakarta.persistence.*;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "recipe")
public class Recipe {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long recipeId;

    //private Long userId;    //SOUVIK

    @Column(nullable = false)
    private String title;

    @Column(nullable = false, length = 1000)
    private String description;

    @Column(nullable = false)
    private String ingredients; // Can be stored as a comma-separated string

    @Column(nullable = false, length = 2000)
    private String instructions;

    @ManyToOne
    @JoinColumn(name = "userId", nullable = false)
    @JsonBackReference
    private User user;

    @OneToMany(mappedBy = "recipe", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<Comment> comments;

    @OneToMany(mappedBy = "recipe", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<Rating> ratings;

    public Long getRecipeId() {
        return recipeId;
    }

    public void setRecipeId(Long recipeId) {
        this.recipeId = recipeId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getIngredients() {
        return ingredients;
    }

    public void setIngredients(String ingredients) {
        this.ingredients = ingredients;
    }

    public String getInstructions() {
        return instructions;
    }

    public void setInstructions(String instructions) {
        this.instructions = instructions;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public List<Comment> getComments() {
        return comments;
    }

    public void setComments(List<Comment> comments) {
        this.comments = comments;
    }

    public List<Rating> getRatings() {
        return ratings;
    }

    public void setRatings(List<Rating> ratings) {
        this.ratings = ratings;
    }

//    public Long getUserId() { //SOUVIK
//        return userId;
//    }
//
//    public void setUserId(Long userId) {    //SOUVIK
//        this.userId = userId;
//    }

    public Recipe(Long recipeId,String title, String description, String ingredients, String instructions, User user,
                  List<Comment> comments, List<Rating> ratings) {
        super();
        this.recipeId = recipeId;
        this.title = title;
        this.description = description;
        this.ingredients = ingredients;
        this.instructions = instructions;
        this.user = user;
        this.comments = comments;
        this.ratings = ratings;
//        this.userId = userId;//SOUVIK
    }

    @Override
    public String toString() {
        return "Recipe [recipeId=" + recipeId + ", title=" + title + ", description=" + description + ", ingredients="
                + ingredients + ", instructions=" + instructions + ", user=" + user + ", comments=" + comments
                + ", ratings=" + ratings + "]";
    }

    public Recipe() {}
}
