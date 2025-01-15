package com.example.demo.controller;


import com.example.demo.exception.ResourceNotFoundException;
import com.example.demo.exception.UnauthorizedAccessException;
import com.example.demo.model.Comment;
import com.example.demo.service.CommentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class CommentController {

    @Autowired
    private CommentService commentService;


    @PostMapping("/api/recipes/{recipeId}/{userId}/{content}")
    public ResponseEntity<Comment> addComment(@PathVariable Long recipeId,
                                              @PathVariable Long userId,
                                              @PathVariable String content) {


        Comment newComment = commentService.addComment(recipeId, userId, content);
        return new ResponseEntity<>(newComment, HttpStatus.CREATED);

    }


    @GetMapping("/api/recipes/{recipeId}/comments")
    public ResponseEntity<List<Comment>> getCommentsByRecipe(@PathVariable Long recipeId) {
        try {
            List<Comment> comments = commentService.getCommentsByRecipe(recipeId);
            return new ResponseEntity<>(comments, HttpStatus.OK);
        } catch (ResourceNotFoundException ex) {
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        }
    }


    @GetMapping("/api/users/{userId}/comments")
    public ResponseEntity<List<Comment>> getCommentsByUser(@PathVariable Long userId) {
        try {
            List<Comment> comments = commentService.getCommentsByUser(userId);
            return new ResponseEntity<>(comments, HttpStatus.OK);
        } catch (ResourceNotFoundException ex) {
            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
        }
    }


//    @PutMapping("/api/recipes/{recipeId}/comments/{commentId}")
//    public ResponseEntity<Comment> updateComment(@PathVariable Long recipeId,
//                                                 @PathVariable Long commentId,
//                                                 @RequestParam Long userId,
//                                                 @RequestParam String newContent) {
//        try {
//            Comment updatedComment = commentService.updateComment(recipeId,commentId, userId, newContent);
//            return new ResponseEntity<>(updatedComment, HttpStatus.OK);
//        } catch (ResourceNotFoundException ex) {
//            return new ResponseEntity<>(null, HttpStatus.NOT_FOUND);
//        } catch (UnauthorizedAccessException ex) {
//            return new ResponseEntity<>(null, HttpStatus.FORBIDDEN);
//        }
//    }


    @DeleteMapping("/{recipeId}/{commentId}/{userId}")
    public ResponseEntity<String> deleteComment(@PathVariable Long recipeId,
                                                @PathVariable Long commentId,
                                                @PathVariable Long userId) {

        commentService.deleteComment(recipeId,commentId, userId);

        return new ResponseEntity<>("Comment deleted successfully", HttpStatus.NO_CONTENT);

    }


    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<String> handleResourceNotFound(ResourceNotFoundException ex) {
        return new ResponseEntity<>(ex.getMessage(), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(UnauthorizedAccessException.class)
    public ResponseEntity<String> handleUnauthorizedAccess(UnauthorizedAccessException ex) {
        return new ResponseEntity<>(ex.getMessage(), HttpStatus.FORBIDDEN);
    }
}
