package com.example.demo.service;

import com.example.demo.model.Recipe;
import com.example.demo.model.User;
import com.example.demo.repository.RecipeRepository;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class RecipeService {
    @Autowired
    private RecipeRepository recipeRepository;
    @Autowired
    private UserRepository userRepository;

    // Method to create a new recipe
    public Recipe createRecipe(Recipe recipe) {
        return recipeRepository.save(recipe);
    }

    // Method to get a recipe by its ID
    public Recipe getRecipeById(Long id) {
        Optional<Recipe> recipe = recipeRepository.findById(id);
        return recipe.orElse(null);
    }

    // Method to update an existing recipe
    public Recipe updateRecipe(Long id, Recipe recipe) {
        if (recipeRepository.existsById(id)) {
            recipe.setRecipeId(id);
            return recipeRepository.save(recipe);
        }
        return null;
    }

    // Method to delete a recipe by its ID
    public void deleteRecipe(Long id) {
        recipeRepository.deleteById(id);
    }

    // Method to search for recipes based on name, ingredient, and category
// public List<Recipe> searchRecipes(String name, String ingredient, String category) {
//    return recipeRepository.findByNameContainingAndIngredientContainingAndCategoryContaining(name, ingredient, category);
//   }

    // Method to find recipes by user ID
    public List<Recipe> findRecipesByUserId(Long userId) {
       Optional<User> user= userRepository.findById(userId);
       if(user.isPresent()){
           return recipeRepository.findByUser(user.get());
       }
        return new ArrayList<>();
    }
}