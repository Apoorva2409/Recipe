package com.example.demo.controller;

import com.example.demo.model.Recipe;
import com.example.demo.service.RecipeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/recipes")
public class RecipeController {
    @Autowired
    private RecipeService recipeService;
    @PostMapping
    public ResponseEntity<Recipe> createRecipe(@RequestBody Recipe recipe) {
        Recipe savedRecipe = recipeService.createRecipe(recipe);
        return ResponseEntity.ok(savedRecipe);
    }
    @GetMapping("/{id}")
    public ResponseEntity<Recipe> getRecipeById(@PathVariable Long id) {
        Recipe recipe = recipeService.getRecipeById(id);
        return ResponseEntity.ok(recipe);
    }
    @PutMapping("/{id}")
    public ResponseEntity<Recipe> updateRecipe(@PathVariable Long id, @RequestBody Recipe recipe) {
        Recipe updatedRecipe = recipeService.updateRecipe(id, recipe);
        return ResponseEntity.ok(updatedRecipe);
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteRecipe(@PathVariable Long id) {
        recipeService.deleteRecipe(id);
        return ResponseEntity.ok("Recipe deleted successfully");
    }
//    @GetMapping("/search")
//    public ResponseEntity<List<Recipe>> searchRecipes(@RequestParam String name, @RequestParam String ingredient, @RequestParam String category) {
//        List<Recipe> recipes = recipeService.searchRecipes(name, ingredient, category);
//        return ResponseEntity.ok(recipes);
//    }
}