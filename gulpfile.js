'use strict';

var gulp = require("gulp");
var sourcemaps = require("gulp-sourcemaps");
var babel = require("gulp-babel");
var concat = require("gulp-concat");


var mocha = require('gulp-mocha');
var babel = require('babel-core/register');


var istanbul = require('gulp-istanbul');
var isparta = require('isparta');

gulp.task('istanbul', cb => {
  gulp.src(['./src/**/*.js'])
  .pipe(istanbul({
    instrumenter: isparta.Instrumenter,
    includeUntested: true,
    babel: { stage: 0 }
  }))
  .pipe(istanbul.hookRequire())
  .on('finish', cb)
})

gulp.task('mocha', function() {
  return gulp.src(['test/**/*.js'])
  .pipe(mocha({
    compilers: {
      js: babel
    }
  }));
});



gulp.task("default", function () {
  return gulp.src("src/**/*.js")
  .pipe(sourcemaps.init())
  .pipe(babel({optional: ['runtime']}))
  .pipe(concat("all.js"))
  .pipe(sourcemaps.write("."))
  .pipe(gulp.dest("dist"));
});
